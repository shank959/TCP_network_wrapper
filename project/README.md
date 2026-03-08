# CS 118 Winter 26 Project 2

## Overview

This project implements a secure transport layer on top of a reliable TCP connection. The security layer handles a TLS-like handshake between a client and server, and then encrypts all subsequent data using AES-256-CBC with HMAC-SHA256 for integrity. Everything is built around TLV (Type-Length-Value) encoded messages.

The only file we edited was `security.c`. All crypto primatives and networking code was provided.

## High Level Design

The security layer is implemented as a state machine with two main functions:
- `input_sec` handles outgoing messages (sending data out to the network)
- `output_sec` handles incoming messages (receiving data from the network)

Both the client and server share the same code, they just start in different states.

### Handshake

The handshake is a 1-RTT exchange:

1. Client sends a CLIENT_HELLO containing protocol version, a random 32-byte nonce, and its ephemeral ECDH public key.
2. Server responds with a SERVER_HELLO containing its own nonce, its certificate (loaded from `server_cert.bin`), its ephemeral public key, and a signature over the handshake transcript.
3. Client verifies the server's certificate (CA signature, lifetime validity, hostname match) and verifies the handshake signature using the server's identity key from the certificate.
4. Both sides derive shared session keys using ECDH + HKDF with the concatenated nonces as salt.

### Data Transfer

After the handshake, all messages are encrypted. Each DATA message contains an IV (random 16 bytes), a MAC (HMAC-SHA256 over the serialized IV and ciphertext TLVs), and the AES-256-CBC ciphertext. On the recieving end, the MAC is verified before decryption to ensure integrity.

## Implementation Details

### Global State

We store `client_nonce` and `server_nonce` as global arrays so they persist across state transitions. This is needed because the nonces are generated in one state but used for key derivation in a later state.

### init_sec

Based on wether we're the client or server:
- Client loads the CA public key (`ca_public_key.bin`) and generates an ephemeral keypair
- Server loads its certificate (`server_cert.bin`) and generates an ephemeral keypair

### Client Hello (input_sec)

We build a CLIENT_HELLO TLV with three children: VERSION_TAG (set to 0x01), NONCE (32 random bytes), and PUBLIC_KEY (our ephemeral key). The TLV is stored globally because the server needs it later to construct/verify the handshake signature.

### Server Hello Receive (output_sec)

The server parses the client hello, validates the protocol version, stores the client nonce, and loads the client's ephemeral public key for later ECDH.

### Server Hello Send (input_sec)

This is where it gets a bit tricky. The server needs to sign the handshake transcript with its identity key, but it also needs its ephemeral key for key derivation. So we save the ephemeral key with `get_private_key()`, load the identity key from `server_key.bin`, sign the transcript, then restore the ephemeral key with `set_private_key()`.

The transcript that gets signed is: serialized(client_hello) + serialized(server_nonce_tlv) + serialized(server_pubkey_tlv).

After sending, we derive the shared secret and session keys.

### Client Server Hello Receive (output_sec)

Most of the verification logic lives here. We do the following checks in order:

1. Verify the CA's signature on the certificate by re-serializing the DNS_NAME, PUBLIC_KEY, and LIFETIME TLVs and checking against `ec_ca_public_key`. Exit code 1 if invalid.
2. Check the certificate lifetime against current time. Exit code 1 if expired, exit code 6 if malformed.
3. Compare the DNS name in the cert to the hostname we connected to. Exit code 2 if mismatch.
4. Verify the handshake signature using the server's identity public key from the cert. Exit code 3 if invalid.

Then we load the server's ephemeral public key (not the identity key from the cert), derive the ECDH secret, and compute session keys.

### Data Send/Receive (input_sec / output_sec in DATA_STATE)

Sending: read plaintext from stdin, encrypt it, compute HMAC over the serialized IV and ciphertext TLVs, package everything into a DATA TLV.

Recieving: deserialize the DATA TLV, recompute the HMAC, compare with the recieved MAC (exit 5 if mismatch), then decrypt and output.

The `inc_mac` flag intentionally corrupts the MAC for testing purposes.

### Helper Functions

- `read_be_uint`: parses big-endian byte sequences into uint64 values
- `parse_lifetime_window`: decodes the 16-byte LIFETIME TLV into not_before/not_after timestamps
- `enforce_lifetime_valid`: checks if current time falls within the certificate's validity window

## Challenges

The trickiest part was getting the handshake signature right -- making sure the transcript was constructed in exactly the same order on both sides. Also had to be careful about when to load which public key (identity vs ephemeral) on the client side during verification.

## Testing

Tested localy by running the server and client from the `keys/` directory. Verified all error cases:
- Bad DNS name -> exit 2
- Expired certificate -> exit 1
- Wrong CA key -> exit 1
- Corrupted MAC -> exit 5
