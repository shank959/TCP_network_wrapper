#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "libsecurity.h"
#include "io.h"
#include "consts.h"

int state_sec = 0;
char *hostname = NULL;
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

// global nonce storage so both sides can use them for key derivation
// ref: piazza Q3 -- store nonces as globals
uint8_t client_nonce[NONCE_SIZE];
uint8_t server_nonce[NONCE_SIZE];

// parses a big-endian byte sequence into a uint64
// e.g. bytes = [0x00, 0x00, 0x00, 0x01] with nbytes=4 => returns 1
static uint64_t read_be_uint(const uint8_t* bytes, size_t nbytes) {
    uint64_t result = 0;
    for (size_t i = 0; i < nbytes; i++) {
        result = (result << 8) | bytes[i];
    }
    return result;
}

// decodes the lifetime tlv value into not_before and not_after timestamps
// the lifetime value is 16 bytes: [not_before (8 bytes BE) || not_after (8 bytes BE)]
// returns false if anything is malformed
static bool parse_lifetime_window(const tlv* life, uint64_t* start_ts, uint64_t* end_ts) {
    if (life == NULL || start_ts == NULL || end_ts == NULL) return false;
    if (life->val == NULL || life->length != 16) return false;

    *start_ts = read_be_uint(life->val, 8);
    *end_ts = read_be_uint(life->val + 8, 8);

    if (*end_ts < *start_ts) return false;
    return true;
}

// checks if the certificate lifetime is valid right now
// exits with code 6 if the lifetime tlv is malformed
// exits with code 1 if the cert is expired or not yet valid
static void enforce_lifetime_valid(const tlv* life) {
    uint64_t start_ts, end_ts;
    if (!parse_lifetime_window(life, &start_ts, &end_ts)) {
        exit(6);
    }
    uint64_t now = (uint64_t) time(NULL);
    if (now < start_ts || now > end_ts) {
        exit(1);
    }
}

void init_sec(int initial_state, char* peer_host, bool bad_mac) {
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();

    if (initial_state == CLIENT_CLIENT_HELLO_SEND) {
        // client: load the CA's public key so we can verify certs later
        load_ca_public_key("ca_public_key.bin");
        generate_private_key();
        derive_public_key();
    } else if (initial_state == SERVER_CLIENT_HELLO_AWAIT) {
        // server: load our certificate (raw bytes) and generate ephemeral keys
        load_certificate("server_cert.bin");
        generate_private_key();
        derive_public_key();
    }
}

ssize_t input_sec(uint8_t* out_buf, size_t out_cap) {
    UNUSED(out_cap);
    switch ( state_sec ) {
    case CLIENT_CLIENT_HELLO_SEND: {
        print("SEND CLIENT HELLO");

        // generate our random nonce
        generate_nonce(client_nonce, NONCE_SIZE);

        // build the version tlv -- single byte with protocol version
        tlv* version = create_tlv(VERSION_TAG);
        uint8_t ver = PROTOCOL_VERSION;
        add_val(version, &ver, 1);

        // build the nonce tlv
        tlv* nonce = create_tlv(NONCE);
        add_val(nonce, client_nonce, NONCE_SIZE);

        // build the public key tlv with our ephemeral pubkey
        tlv* pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);

        // wrap everything in a CLIENT_HELLO container
        client_hello = create_tlv(CLIENT_HELLO);
        add_tlv(client_hello, version);
        add_tlv(client_hello, nonce);
        add_tlv(client_hello, pk);

        // serialize and send
        uint16_t len = serialize_tlv(out_buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t) len;
    }
    case SERVER_SERVER_HELLO_SEND: {
        print("SEND SERVER HELLO");

        // generate server nonce
        generate_nonce(server_nonce, NONCE_SIZE);

        // 1) nonce tlv
        tlv* nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, server_nonce, NONCE_SIZE);

        // 2) certificate tlv, deserialize the raw cert bytes loaded in init_sec
        tlv* cert_tlv = deserialize_tlv(certificate, cert_size);

        // 3) ephemeral public key tlv
        tlv* pk_tlv = create_tlv(PUBLIC_KEY);
        add_val(pk_tlv, public_key, pub_key_size);

        // 4) handshake signature
        // the transcript to sign is: serialize(client_hello) + serialize(nonce_tlv) + serialize(pk_tlv) (on readmE)
        uint8_t transcript[2000];
        uint16_t offset = 0;
        offset += serialize_tlv(transcript + offset, client_hello);
        offset += serialize_tlv(transcript + offset, nonce_tlv);
        offset += serialize_tlv(transcript + offset, pk_tlv);

        // temporarily switch to the server's identity key to sign
        EVP_PKEY* eph_key = get_private_key();
        load_private_key("server_key.bin");

        uint8_t sig_buf[256];
        size_t sig_len = sign(sig_buf, transcript, offset);

        // restore ephemeral key for ECDH
        set_private_key(eph_key);

        tlv* sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig_tlv, sig_buf, sig_len);

        // assemble the SERVER_HELLO container
        server_hello = create_tlv(SERVER_HELLO);
        add_tlv(server_hello, nonce_tlv);
        add_tlv(server_hello, cert_tlv);
        add_tlv(server_hello, pk_tlv);
        add_tlv(server_hello, sig_tlv);
        uint16_t len = serialize_tlv(out_buf, server_hello);

        // derive session keys -- peer pubkey was loaded when we received the client hello
        derive_secret();

        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        state_sec = DATA_STATE;
        return (ssize_t) len;
    }
    case DATA_STATE: {
        // read plaintext from stdin
        uint8_t plain[5000];
        ssize_t plain_len = input_io(plain, sizeof(plain));
        if (plain_len <= 0) 
            return 0;

        // encrypt the plaintext
        uint8_t iv_buf[IV_SIZE];
        uint8_t cipher_buf[5000];
        size_t cipher_len = encrypt_data(iv_buf, cipher_buf, plain, plain_len);

        // build iv and ciphertext tlvs
        tlv* iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv_buf, IV_SIZE);

        tlv* ct_tlv = create_tlv(CIPHERTEXT);
        add_val(ct_tlv, cipher_buf, cipher_len);

        // compute hmac over serialized(iv_tlv) + serialized(ct_tlv)
        uint8_t mac_data[5000];
        uint16_t mac_data_len = 0;
        """
        mac_data_len += serialize_tlv(mac_data + mac_data_len, iv_tlv);
        """
        mac_data_len += serialize_tlv(mac_data + mac_data_len, iv_tlv);
        mac_data_len += serialize_tlv(mac_data + mac_data_len, ct_tlv);

        uint8_t mac_buf[MAC_SIZE];
        hmac(mac_buf, mac_data, mac_data_len);

        // for testing bad mac ; intentionally corrupt
        if (inc_mac) {
            mac_buf[0] ^= 0xFF;
        }

        tlv* mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac_buf, MAC_SIZE);

        // build the DATA container: IV, MAC, CIPHERTEXT
        tlv* data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, iv_tlv);
        add_tlv(data_tlv, mac_tlv);
        add_tlv(data_tlv, ct_tlv);

        uint16_t len = serialize_tlv(out_buf, data_tlv);
        free_tlv(data_tlv);
        return (ssize_t) len;
    }
    default:
        return (ssize_t) 0;
    }
}

void output_sec(uint8_t* in_buf, size_t in_len) {
    switch (state_sec) {
    case SERVER_CLIENT_HELLO_AWAIT: {
        print("RECV CLIENT HELLO");

        // deserialize the incoming client hello
        client_hello = deserialize_tlv(in_buf, in_len);
        if (client_hello == NULL) 
            exit(6);

        // extract required children
        tlv* version = get_tlv(client_hello, VERSION_TAG);
        tlv* nonce = get_tlv(client_hello, NONCE);
        tlv* pk = get_tlv(client_hello, PUBLIC_KEY);

        if (version == NULL || nonce == NULL || pk == NULL) 
            exit(6); // short circuit eval ma3ybe?

        // check protocol version
        if (version->val[0] != PROTOCOL_VERSION) 
            exit(6);

        // store the client nonce for key derivation later
        memcpy(client_nonce, nonce->val, NONCE_SIZE);

        // load the client's ephemeral public key
        load_peer_public_key(pk->val, pk->length);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT: {
        print("RECV SERVER HELLO");

        // deserialize the server hello
        server_hello = deserialize_tlv(in_buf, in_len);
        if (server_hello == NULL) 
            exit(6);

        // extracz
        tlv* srv_nonce = get_tlv(server_hello, NONCE);
        tlv* cert = get_tlv(server_hello, CERTIFICATE);
        tlv* srv_eph_pk = get_tlv(server_hello, PUBLIC_KEY);
        tlv* hs_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);
        if (srv_nonce == NULL || cert == NULL || srv_eph_pk == NULL || hs_sig == NULL) 
            exit(6);

        // store server noncee
        memcpy(server_nonce, srv_nonce->val, NONCE_SIZE);

        // cert verif !TODO shan take a look to see if properly implemented
        tlv* dns = get_tlv(cert, DNS_NAME);
        tlv* cert_pk = get_tlv(cert, PUBLIC_KEY);
        tlv* lifetime = get_tlv(cert, LIFETIME);
        tlv* cert_sig = get_tlv(cert, SIGNATURE);

        if (dns == NULL || cert_pk == NULL || lifetime == NULL || cert_sig == NULL) exit(6);

        // 1) verify the CA's signature on the certificate
        //  the cert signature covers: serialize(dns) + serialize(cert_pk) + serialize(lifetime) (CHECK SPEC)
        uint8_t cert_verify_buf[1000];
        uint16_t cert_offset = 0;
        cert_offset += serialize_tlv(cert_verify_buf + cert_offset, dns);
        cert_offset += serialize_tlv(cert_verify_buf + cert_offset, cert_pk);
        cert_offset += serialize_tlv(cert_verify_buf + cert_offset, lifetime);

        int cert_valid = verify(cert_sig->val, cert_sig->length, cert_verify_buf, cert_offset, ec_ca_public_key);
        if (cert_valid != 1) exit(1);

        // 2) check certificate lifetime
        enforce_lifetime_valid(lifetime);

        // 3) check that the dns name matches the hostname we cconnect??
        if (strcmp((char*)dns->val, hostname) != 0) exit(2);

        // handshakeroni

        // load the server's identity public key (from the cert) to verify the handshake sig
        load_peer_public_key(cert_pk->val, cert_pk->length);

        // rebuild the transcript: serialize(client_hello) + serialize(srv_nonce_tlv) + serialize(srv_eph_pk_tlv)
        uint8_t transcript[2000];
        uint16_t t_offset = 0;
        t_offset += serialize_tlv(transcript + t_offset, client_hello);
        t_offset += serialize_tlv(transcript + t_offset, srv_nonce);
        t_offset += serialize_tlv(transcript + t_offset, srv_eph_pk);

        int hs_valid = verify(hs_sig -> val, hs_sig -> length, transcript, t_offset, ec_peer_public_key);
        if (hs_valid != 1) 
            exit(3);

        // key deriv

        // now load the server's EPHEMERAL public key for the ECDH secret
        load_peer_public_key(srv_eph_pk->val, srv_eph_pk->length);
        derive_secret();
        uint8_t salt[NONCE_SIZE * 2];
        memcpy(salt, client_nonce, NONCE_SIZE);
        memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
        derive_keys(salt, sizeof(salt));

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE: {
        // deserialize the incoming data message
        tlv* data_tlv = deserialize_tlv(in_buf, in_len);
        if (data_tlv == NULL) exit(6);

        tlv* iv_tlv = get_tlv(data_tlv, IV);
        tlv* mac_tlv = get_tlv(data_tlv, MAC);
        tlv* ct_tlv = get_tlv(data_tlv, CIPHERTEXT);

        if (iv_tlv == NULL || mac_tlv == NULL || ct_tlv == NULL) exit(6);

        // recompute the mac over serialized(iv_tlv) + serialized(ct_tlv)
        uint8_t mac_data[5000];
        uint16_t mac_data_len = 0;
        mac_data_len += serialize_tlv(mac_data + mac_data_len, iv_tlv);
        mac_data_len += serialize_tlv(mac_data + mac_data_len, ct_tlv);

        uint8_t computed_mac[MAC_SIZE];
        hmac(computed_mac, mac_data, mac_data_len);

        // tamperment checking // !TODO AYAAN CHECK IF CORRECTLY IMPLEMENTED
        """ if (memcmp(computed_mac, val, MAC_SIZE) != 0) exit(3); """
        if (memcmp(computed_mac, mac_tlv->val, MAC_SIZE) != 0) exit(5);

        // decrypt and output the plaintext
        uint8_t plain[5000];
        size_t plain_len = decrypt_cipher(plain, ct_tlv->val, ct_tlv->length, iv_tlv->val);

        output_io(plain, plain_len);
        free_tlv(data_tlv);
        break;
    }
    default:
        break;
    }
}
