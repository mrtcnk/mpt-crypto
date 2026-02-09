#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <secp256k1.h>
#include <openssl/rand.h>
#include "secp256k1_mpt.h"

/* IMPROVED MACRO: Robust error checking that works in Release mode */
#define EXPECT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CRITICAL FAILURE: %s\nFile: %s, Line: %d\nCode: %s\n", \
        msg, __FILE__, __LINE__, #cond); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

/* Helper to dump pubkey bytes for debugging */
static void dump_pubkey_raw(const char* name, const secp256k1_pubkey* pk) {
    const unsigned char* p = (const unsigned char*)pk;
    printf("%s raw: ", name);
    for (size_t i = 0; i < sizeof(*pk); i++) printf("%02x", p[i]);
    printf("\n");
}

/* Helper to get a random 32-byte scalar */
static int get_random_scalar(const secp256k1_context* ctx, unsigned char* scalar) {
    secp256k1_pubkey temp_pubkey;
    int ret = secp256k1_elgamal_generate_keypair(ctx, scalar, &temp_pubkey);

    // Safety check: ensure we didn't get all zeros
    if (ret) {
        int is_zero = 1;
        for(int i=0; i<32; i++) if(scalar[i] != 0) is_zero = 0;
        if(is_zero) {
            fprintf(stderr, "CRITICAL: get_random_scalar produced ALL ZEROS!\n");
            return 0;
        }
    }
    return ret;
}

/**
 * Test 1: Valid proof generation and verification.
 */
static void test_same_plaintext_valid(const secp256k1_context* ctx) {
    unsigned char priv_1[32], priv_2[32];
    secp256k1_pubkey pub_1, pub_2;
    unsigned char r1[32], r2[32];
    unsigned char tx_context_id[32];
    uint64_t amount_m = 123456;

    secp256k1_pubkey R1, S1, R2, S2;
    unsigned char proof[261];

    printf("Running test: same plaintext proof (valid case)...\n");

    // 1. Setup: Generate keys and randomness
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &pub_1) == 1, "Failed to generate keypair 1");
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &pub_2) == 1, "Failed to generate keypair 2");
    EXPECT(get_random_scalar(ctx, r1) == 1, "Failed to generate r1");
    EXPECT(get_random_scalar(ctx, r2) == 1, "Failed to generate r2");
    EXPECT(get_random_scalar(ctx, tx_context_id) == 1, "Failed to generate tx context");

    // 2. Encrypt the same amount
    EXPECT(secp256k1_elgamal_encrypt(ctx, &R1, &S1, &pub_1, amount_m, r1) == 1, "Encryption 1 failed");
    EXPECT(secp256k1_elgamal_encrypt(ctx, &R2, &S2, &pub_2, amount_m, r2) == 1, "Encryption 2 failed");

    printf("Generating proof...\n");
    // 3. Generate the proof
    EXPECT(secp256k1_mpt_prove_same_plaintext(
            ctx, proof,
            &R1, &S1, &pub_1,
            &R2, &S2, &pub_2,
            amount_m, r1, r2, tx_context_id
    ) == 1, "Proof generation failed");

    printf("Verifying proof...\n");
    // 4. Verify the proof
    EXPECT(secp256k1_mpt_verify_same_plaintext(
            ctx, proof,
            &R1, &S1, &pub_1,
            &R2, &S2, &pub_2,
            tx_context_id
    ) == 1, "Proof verification failed");

    printf("Test passed!\n");
}

/**
 * Test 2: Verifying a tampered proof (should fail).
 */
static void test_same_plaintext_tampered_proof(const secp256k1_context* ctx) {
    unsigned char priv_1[32], priv_2[32];
    secp256k1_pubkey pub_1, pub_2;
    unsigned char r1[32], r2[32];
    unsigned char tx_context_id[32];
    uint64_t amount_m = 123456;
    secp256k1_pubkey R1, S1, R2, S2;
    unsigned char proof[261];

    printf("Running test: same plaintext proof (tampered proof)...\n");

    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &pub_1) == 1, "Setup failed");
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &pub_2) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, r1) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, r2) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, tx_context_id) == 1, "Setup failed");

    EXPECT(secp256k1_elgamal_encrypt(ctx, &R1, &S1, &pub_1, amount_m, r1) == 1, "Encryption failed");
    EXPECT(secp256k1_elgamal_encrypt(ctx, &R2, &S2, &pub_2, amount_m, r2) == 1, "Encryption failed");

    EXPECT(secp256k1_mpt_prove_same_plaintext(
            ctx, proof, &R1, &S1, &pub_1, &R2, &S2, &pub_2,
            amount_m, r1, r2, tx_context_id) == 1, "Proof gen failed");

    // Tamper with the proof
    proof[42] ^= 0x01;

    // Verify should fail (return 0)
    int result = secp256k1_mpt_verify_same_plaintext(
            ctx, proof, &R1, &S1, &pub_1, &R2, &S2, &pub_2, tx_context_id);

    EXPECT(result == 0, "Tampered proof was ACCEPTED! (Expected failure)");

    printf("Test passed!\n");
}

/**
 * Test 3: Verifying with different-amount ciphertexts (should fail).
 */
static void test_same_plaintext_wrong_ciphertext(const secp256k1_context* ctx) {
    unsigned char priv_1[32], priv_2[32];
    secp256k1_pubkey pub_1, pub_2;
    unsigned char r1[32], r2[32], r3[32];
    unsigned char tx_context_id[32];
    uint64_t amount_m1 = 123456;
    uint64_t amount_m2 = 777777;

    secp256k1_pubkey R1, S1, R2, S2;
    secp256k1_pubkey R3, S3;
    unsigned char proof[261];

    printf("Running test: same plaintext proof (wrong ciphertext)...\n");

    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_1, &pub_1) == 1, "Setup failed");
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, priv_2, &pub_2) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, r1) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, r2) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, r3) == 1, "Setup failed");
    EXPECT(get_random_scalar(ctx, tx_context_id) == 1, "Setup failed");

    EXPECT(secp256k1_elgamal_encrypt(ctx, &R1, &S1, &pub_1, amount_m1, r1) == 1, "Encryption failed");
    EXPECT(secp256k1_elgamal_encrypt(ctx, &R2, &S2, &pub_2, amount_m1, r2) == 1, "Encryption failed");
    EXPECT(secp256k1_elgamal_encrypt(ctx, &R3, &S3, &pub_2, amount_m2, r3) == 1, "Encryption failed");

    // Generate valid proof for m1
    EXPECT(secp256k1_mpt_prove_same_plaintext(
            ctx, proof, &R1, &S1, &pub_1, &R2, &S2, &pub_2,
            amount_m1, r1, r2, tx_context_id) == 1, "Proof gen failed");

    // Verify against R3/S3 (which is m2) - Should fail
    int result = secp256k1_mpt_verify_same_plaintext(
            ctx, proof, &R1, &S1, &pub_1, &R3, &S3, &pub_2, tx_context_id);

    EXPECT(result == 0, "Wrong ciphertext was ACCEPTED! (Expected failure)");

    printf("Test passed!\n");
}

int main() {
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    EXPECT(ctx != NULL, "Failed to create context");

    unsigned char seed[32];
    EXPECT(RAND_bytes(seed, sizeof(seed)) == 1, "RAND_bytes failed");
    EXPECT(secp256k1_context_randomize(ctx, seed) == 1, "Context randomization failed");

    test_same_plaintext_valid(ctx);
    test_same_plaintext_tampered_proof(ctx);
    test_same_plaintext_wrong_ciphertext(ctx);

    secp256k1_context_destroy(ctx);
    return 0;
}