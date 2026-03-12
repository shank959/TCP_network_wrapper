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
//keep this heare in case we want a separate identity/private key handle later
EVP_PKEY *priv_key = NULL;
tlv *client_hello = NULL;
tlv *server_hello = NULL;
bool inc_mac = false;

// global nonce storage so both sides can use them for key derivation (piazza said to store nonces as globals)
uint8_t client_nonce[NONCE_SIZE];
uint8_t server_nonce[NONCE_SIZE];

// ========================= HELPER FUNCTIONS =========================

static uint64_t read_be_uint(const uint8_t *bytes, size_t nbytes)
{
        // TODO: parse an unsigned integer from a big-endian byte sequence.
        // Hint: this is used for certificate lifetime fields.

    //uint64_t result = 0;
    // size_t i = 0;
    // while (i < nbytes) {
    //     uint64_t shift_amount = (nbytes-1-i) * 8;
    //     result += ((uint64_t)bytes[i] << shift_amount);
    //     i++;
    // }
    // loop thruogh bytes and shift left by 8 bits
    //for (size_t i = 0; i < nbytes; i++)
    //{
        //result = (result << 8) | bytes[i];
    //}
    //return result;

    uint64_t value = 0;

    while( nbytes-- > 0)
    {
        value = (value << 8) | *bytes++;
    }

    return value;
}

static bool parse_lifetime_window(const tlv *life, uint64_t *start_ts, uint64_t *end_ts)
{

        // TODO: decode [not_before || not_after] from CERTIFICATE/LIFETIME.
        // Return false on malformed input (NULL pointers, wrong length, invalid range).

        // if (life != NULL && start_ts != NULL && end_ts != NULL) {
        //     if (life->val != NULL && life->length == 16) {
        //         start_ts = read_be_uint(life->val, 8);
        //         end_ts = read_be_uint(life->val + 8, 8);
        //         if (*end_ts >= *start_ts) {
        //             return true; // return true if everything is valid
        //         }
        //     }
        // }

        // check if this ltv logic still works
    if (life == NULL || start_ts == NULL || end_ts == NULL)
    {
        return false;
    }
    if (life->val == NULL || life->length != 16)
    {
        return false;
    }
    // parse the lifetime value
    *start_ts = read_be_uint(life->val, 8);
    *end_ts = read_be_uint(life->val + 8, 8);

    return *end_ts >= *start_ts;
}

static void enforce_lifetime_valid(const tlv *life)
{

    // TODO: enforce lifetime validity against current time.
    // Exit with code 1 for invalid/expired cert, code 6 for malformed time inputs.

    uint64_t start_ts = 0;
    uint64_t end_ts = 0;
    uint64_t now = 0;

    if(!parse_lifetime_window(life, &start_ts, &end_ts))
    {
        exit(6);
    }

    now = (uint64_t)time(NULL);

    if(now < start_ts || now > end_ts)
    {
        exit(1);
    }
}

//MORE HELPER FUNCTIONS
//helper to buid the handshake transcript used for signing/verifying. Both client and server must contruct transcript in same order
static uint16_t build_handshake_transcript(uint8_t *buf, tlv *hello_tlv, tlv *nonce_tlv, tlv *pk_tlv)
{
    uint16_t len = 0;
    len += serialize_tlv(buf + len, hello_tlv);
    len += serialize_tlv(buf + len, nonce_tlv);
    len += serialize_tlv(buf + len, pk_tlv);
    return len;
}

//After the ECDH shared secret is derived, both sides use two nonces
//as salt input to HKDF to derive the symmetric encription keys
static void derive_session_keys_from_nonces(void)
{
    uint8_t salt[NONCE_SIZE * 2];
    memcpy(salt, client_nonce, NONCE_SIZE);
    memcpy(salt + NONCE_SIZE, server_nonce, NONCE_SIZE);
    derive_keys(salt, sizeof(salt));
}

//Helps rebiuld exact byte sequence
static uint16_t serialize_mac_parts(uint8_t *buf, tlv *iv_tlv, tlv *ct_tlv)
{
    uint16_t len = 0;
    len += serialize_tlv(buf +len, iv_tlv);
    len += serialize_tlv(buf +len, ct_tlv);
    return len;
}

void init_sec(int initial_state, char *peer_host, bool bad_mac)
{
    state_sec = initial_state;
    hostname = peer_host;
    inc_mac = bad_mac;
    init_io();

    // TODO: initialize keys and role-specific state.
    // Client side: load CA public key and prepare ephemeral keypair.
    // Server side: load certificate and prepare ephemeral keypair.

    if (initial_state == CLIENT_CLIENT_HELLO_SEND)
    {
        // client side: load the CAs public key so we can verify certs
        load_ca_public_key("ca_public_key.bin");
        generate_private_key();
        derive_public_key();
    }
    else if (initial_state == SERVER_CLIENT_HELLO_AWAIT)
    {
        // server side: load our certificate and generate temp keys
        load_certificate("server_cert.bin");
        generate_private_key();
        derive_public_key();
    }
}

ssize_t input_sec(uint8_t *out_buf, size_t out_cap)
{
    UNUSED(out_cap);

    switch (state_sec)
    {
    case CLIENT_CLIENT_HELLO_SEND:
    {
        print("SEND CLIENT HELLO");
        // TODO: build CLIENT_HELLO with VERSION_TAG, NONCE, and PUBLIC_KEY TLVs.
        // Save client nonce for later key derivation and advance to CLIENT_SERVER_HELLO_AWAIT.

        // generate our random nonce
        generate_nonce(client_nonce, NONCE_SIZE);

        // build the tlv with version tag
        tlv *version = create_tlv(VERSION_TAG);
        uint8_t ver = PROTOCOL_VERSION;
        add_val(version, &ver, 1); // add the version tag to the tlv

        // build the nonce tlv
        tlv *nonce = create_tlv(NONCE);
        add_val(nonce, client_nonce, NONCE_SIZE);

        // build the public key tlv with our temp pubkey
        tlv *pk = create_tlv(PUBLIC_KEY);
        add_val(pk, public_key, pub_key_size);

        // wrap evreything in a CLIENT_HELLO container
        client_hello = create_tlv(CLIENT_HELLO);
        add_tlv(client_hello, version);
        add_tlv(client_hello, nonce);
        add_tlv(client_hello, pk);

        // serialize and send
        uint16_t len = serialize_tlv(out_buf, client_hello);
        state_sec = CLIENT_SERVER_HELLO_AWAIT;
        return (ssize_t)len;
    }
    case SERVER_SERVER_HELLO_SEND:
    {
        print("SEND SERVER HELLO");
        // TODO: build SERVER_HELLO with NONCE, CERTIFICATE, PUBLIC_KEY, HANDSHAKE_SIGNATURE.
        // Sign the expected handshake transcript, derive session keys, then enter DATA_STATE.

        // generate server nonce
        generate_nonce(server_nonce, NONCE_SIZE);

        // === build server hello children ===

        // 1. nonce tlv
        tlv *nonce_tlv = create_tlv(NONCE);
        add_val(nonce_tlv, server_nonce, NONCE_SIZE);

        // 2.cert tlv - deserialize raw cert
        tlv *cert_tlv = deserialize_tlv(certificate, cert_size);

        // 3. temp pubkey tlv
        tlv *pk_tlv = create_tlv(PUBLIC_KEY);
        add_val(pk_tlv, public_key, pub_key_size);

        // 4. handshake signature
        // todo fix create transcript with signing
        // uint8_t part1[700], part2[700], part3[700];
        // uint16_t len1 = serialize_tlv(part1, client_hello);
        // uint16_t len2 = serialize_tlv(part2, nonce_tlv);
        // uint16_t len3 = serialize_tlv(part3, pk_tlv);
        // memcpy(transcript, part1, len1);
        // memcpy(transcript + len1, part2, len2);
        // memcpy(transcript + len1 + len2, part3, len3);
        // offset = len1 + len2 + len3;
        uint8_t transcript[2000];
        uint16_t transcript_len = build_handshake_transcript(transcript, client_hello, nonce_tlv, pk_tlv);

        // temporarily switch to the servers identity key to sign
        EVP_PKEY *eph_key = get_private_key();
        load_private_key("server_key.bin");
        uint8_t sig_buf[256];
        size_t sig_len = sign(sig_buf, transcript, transcript_len);

        // restore temp key for ECDH
        set_private_key(eph_key);
        tlv *sig_tlv = create_tlv(HANDSHAKE_SIGNATURE);
        add_val(sig_tlv, sig_buf, sig_len);

        // wrap everything in a SERVER_HELLO container
        server_hello = create_tlv(SERVER_HELLO);
        add_tlv(server_hello, nonce_tlv);
        add_tlv(server_hello, cert_tlv);
        add_tlv(server_hello, pk_tlv);
        add_tlv(server_hello, sig_tlv);
        uint16_t len = serialize_tlv(out_buf, server_hello);

        // derive secret key
        derive_secret();

        // todo fix salt logic
        // uint8_t salt[NONCE_SIZE * 2];
        // for (size_t i = 0; i < NONCE_SIZE; i++) salt[i] = client_nonce[i];
        // for (size_t i = 0; i < NONCE_SIZE; i++) salt[NONCE_SIZE + i] = server_nonce[i];
        // derive_keys(salt, sizeof(salt));
        derive_session_keys_from_nonces();

        state_sec = DATA_STATE;
        return (ssize_t)len;
    }
    case DATA_STATE:
    {
        // TODO: read plaintext from stdin, encrypt it, compute MAC, serialize DATA TLV.
        // If `inc_mac` is true, intentionally corrupt the MAC for testing.
        // read plaintext from stdin
        uint8_t plain[5000];
        ssize_t plain_len = input_io(plain, sizeof(plain));
        if (plain_len <= 0)
        {
            return 0;
        }

        // encrypt plaintxt
        uint8_t iv_buf[IV_SIZE];
        uint8_t cipher_buf[5000];
        size_t cipher_len = encrypt_data(iv_buf, cipher_buf, plain, plain_len);

        // Build iv and ciphertext tlvs
        tlv *iv_tlv = create_tlv(IV);
        add_val(iv_tlv, iv_buf, IV_SIZE);

        tlv *ct_tlv = create_tlv(CIPHERTEXT);
        add_val(ct_tlv, cipher_buf, cipher_len);

        // compute hmac over iv_tlv + ct_tlv (need to serialize)
        uint8_t mac_data[5000];
        uint16_t mac_data_len = serialize_mac_parts(mac_data, iv_tlv, ct_tlv);

        uint8_t mac_buf[MAC_SIZE];
        hmac(mac_buf, mac_data, mac_data_len);

        // for testing bad mac
        if (inc_mac)
        {
            mac_buf[0] ^= 0xFF;
        }

        tlv *mac_tlv = create_tlv(MAC);
        add_val(mac_tlv, mac_buf, MAC_SIZE);

        // build the data tlv: IV/ MAC/CIPHERTEXT
        tlv *data_tlv = create_tlv(DATA);
        add_tlv(data_tlv, iv_tlv);
        add_tlv(data_tlv, mac_tlv);
        add_tlv(data_tlv, ct_tlv);

        uint16_t len = serialize_tlv(out_buf, data_tlv);
        free_tlv(data_tlv);
        return (ssize_t)len;
    }
    default:
        return (ssize_t)0;
    }
}

void output_sec(uint8_t *in_buf, size_t in_len)
{
    switch (state_sec)
    {
    case SERVER_CLIENT_HELLO_AWAIT:
    {
        print("RECV CLIENT HELLO");
        // TODO: parse CLIENT_HELLO, validate required fields and protocol version.
        // Load peer ephemeral key, store client nonce, and transition to SERVER_SERVER_HELLO_SEND.

        // deserialize the incoming client hello
        client_hello = deserialize_tlv(in_buf, in_len);
        if (client_hello == NULL)
        {
            exit(6); // readme exit codes
        }

        // extract required children
        tlv *version = get_tlv(client_hello, VERSION_TAG);
        tlv *nonce = get_tlv(client_hello, NONCE);
        tlv *pk = get_tlv(client_hello, PUBLIC_KEY);

        // check if any of the required children are missing
        if (version == NULL || nonce == NULL || pk == NULL)
        {
            exit(6); // readme exit codes
        }

        // check protocol version
        if (version->val[0] != PROTOCOL_VERSION)
        {
            exit(6); // readme
        }

        // store client nonce
        memcpy(client_nonce, nonce->val, NONCE_SIZE);

        // load client pubkey
        load_peer_public_key(pk->val, pk->length);

        state_sec = SERVER_SERVER_HELLO_SEND;
        break;
    }
    case CLIENT_SERVER_HELLO_AWAIT:
    {
        print("RECV SERVER HELLO");
        // TODO: parse SERVER_HELLO and verify certificate chain/lifetime/hostname.
        // Verify handshake signature, load server ephemeral key, derive keys, enter DATA_STATE.
        // Required exit codes: bad cert(1), bad identity(2), bad handshake sig(3), malformed(6).

        // deserialize the server hello
        server_hello = deserialize_tlv(in_buf, in_len);
        if (server_hello == NULL)
        {
            exit(6);
        }

        // extract all the pieces we need
        tlv *srv_nonce = get_tlv(server_hello, NONCE);
        tlv *cert = get_tlv(server_hello, CERTIFICATE);
        tlv *srv_eph_pk = get_tlv(server_hello, PUBLIC_KEY);
        tlv *hs_sig = get_tlv(server_hello, HANDSHAKE_SIGNATURE);

        if (srv_nonce == NULL || cert == NULL || srv_eph_pk == NULL || hs_sig == NULL)
        {
            exit(6);
        }

        // store dhe server nonce
        memcpy(server_nonce, srv_nonce->val, NONCE_SIZE);

        // certificate verificatoin
        tlv *dns = get_tlv(cert, DNS_NAME);
        tlv *cert_pk = get_tlv(cert, PUBLIC_KEY);
        tlv *lifetime = get_tlv(cert, LIFETIME);
        tlv *cert_sig = get_tlv(cert, SIGNATURE);

        if (dns == NULL || cert_pk == NULL || lifetime == NULL || cert_sig == NULL)
        {
            exit(6);
        }

        // verify the CAs signature on the cert
        uint8_t cert_verify_buf[1000];
        uint16_t cert_offset = 0;
        cert_offset += serialize_tlv(cert_verify_buf + cert_offset, dns);
        cert_offset += serialize_tlv(cert_verify_buf + cert_offset, cert_pk);
        cert_offset += serialize_tlv(cert_verify_buf + cert_offset, lifetime);

        int cert_valid = verify(cert_sig->val, cert_sig->length, cert_verify_buf, cert_offset, ec_ca_public_key);
        if (cert_valid != 1)
        {
            exit(1);
        }

        // check cert lifetime
        enforce_lifetime_valid(lifetime);

        // check that the dns name matches hostname we connected to
        if (strcmp((char *)dns->val, hostname) != 0)
            exit(2);

        // handshake signature verification
        // load the servers identity key (from the cert) to verify the handshake sig
        load_peer_public_key(cert_pk->val, cert_pk->length);

        // rebuild the transcript: client_hello + srv_nonce + srv_eph_pk (need to serialize)
        uint8_t transcript[2000];
        uint16_t transcript_len = build_handshake_transcript(transcript, client_hello, srv_nonce, srv_eph_pk);

        int hs_valid = verify(hs_sig->val, hs_sig->length, transcript, transcript_len, ec_peer_public_key); // todo fix
        if (hs_valid != 1)
        {
            exit(3);
        }

        // key derivation

        // load the servers ephemeral key for the ECDH secret
        load_peer_public_key(srv_eph_pk->val, srv_eph_pk->length);
        derive_secret();
        derive_session_keys_from_nonces();

        state_sec = DATA_STATE;
        break;
    }
    case DATA_STATE:
    {
        // deserialize the incoming data message
        tlv *data_tlv = deserialize_tlv(in_buf, in_len);
        if (data_tlv == NULL)
            exit(6);

        tlv *iv_tlv = get_tlv(data_tlv, IV);
        tlv *mac_tlv = get_tlv(data_tlv, MAC);
        tlv *ct_tlv = get_tlv(data_tlv, CIPHERTEXT);

        if (iv_tlv == NULL || mac_tlv == NULL || ct_tlv == NULL)
            exit(6);

        // recompute the mac over iv_tlv + ct_tlv (need to serialize)
        uint8_t mac_data[5000];
        uint16_t mac_data_len = serialize_mac_parts(mac_data, iv_tlv, ct_tlv);

        uint8_t computed_mac[MAC_SIZE];
        hmac(computed_mac, mac_data, mac_data_len);

        // compare : if there is a mismatch the message was tampered with
        if (memcmp(computed_mac, mac_tlv->val, MAC_SIZE) != 0)
            exit(5);

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
