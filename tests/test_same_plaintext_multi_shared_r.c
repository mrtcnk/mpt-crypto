#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <secp256k1.h>
#include "secp256k1_mpt.h"

/* Robust error checking that works in Release mode */
#define EXPECT(cond, msg) do { \
    if (!(cond)) { \
        fprintf(stderr, "CRITICAL FAILURE: %s\nFile: %s, Line: %d\nCode: %s\n", \
        msg, __FILE__, __LINE__, #cond); \
        exit(EXIT_FAILURE); \
    } \
} while(0)

int main() {
    secp256k1_context *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    EXPECT(ctx != NULL, "Failed to create secp256k1 context");

    unsigned char seed[32];
    FILE *fr = fopen("/dev/urandom", "r");
    EXPECT(fr != NULL, "Failed to open /dev/urandom");
    EXPECT(fread(seed, 1, 32, fr) == 32, "Failed to read random seed");
    fclose(fr);

    EXPECT(secp256k1_context_randomize(ctx, seed), "Context randomization failed");

    printf("=== Running Test: Proof of Equality (Shared Randomness) ===\n");

    const int N_RECIPIENTS = 3;
    printf("Generating proof for %d recipients...\n", N_RECIPIENTS);

    // 1. Setup
    uint64_t amount = 123456789;
    unsigned char r[32]; // Shared randomness
    unsigned char tx_context[32];

    // DUMMY VAR: Required because we cannot pass NULL to generate_keypair
    secp256k1_pubkey dummy_pk;

    // Generate valid random scalar r (loop ensures non-zero)
    int valid_scalar = 0;
    for (int i = 0; i < 100; i++) {
        // FIX: Pass &dummy_pk instead of NULL
        if (secp256k1_elgamal_generate_keypair(ctx, r, &dummy_pk)) {
            if (secp256k1_ec_seckey_verify(ctx, r)) {
                valid_scalar = 1;
                break;
            }
        }
    }
    EXPECT(valid_scalar, "Failed to generate valid random scalar 'r'");

    // Generate random tx context bytes
    // FIX: Pass &dummy_pk instead of NULL
    EXPECT(secp256k1_elgamal_generate_keypair(ctx, tx_context, &dummy_pk), "Failed to generate tx context");

    // 2. Generate Recipient Keys & Encrypt
    secp256k1_pubkey pks[3];
    secp256k1_pubkey C2s[3];
    secp256k1_pubkey C1; // Shared C1

    // Pre-calculate Shared C1: C1 = r*G
    EXPECT(secp256k1_ec_pubkey_create(ctx, &C1, r), "Failed to create shared C1 commitment");

    for (int i = 0; i < N_RECIPIENTS; i++) {
        unsigned char sk[32];
        EXPECT(secp256k1_elgamal_generate_keypair(ctx, sk, &pks[i]), "Failed to generate recipient keypair");

        // Manually constructing ciphertexts to match the shared 'r' structure:
        // C2[i] = amount*G + r*PK[i]

        // a. Calculate amount*G
        secp256k1_pubkey mG;
        unsigned char m_scalar[32] = {0};
        for(int b=0; b<8; b++) m_scalar[31-b] = (amount >> (b*8)) & 0xFF;

        EXPECT(secp256k1_ec_pubkey_create(ctx, &mG, m_scalar), "Failed to create amount commitment mG");

        // b. Calculate r*PK[i]
        secp256k1_pubkey rPK = pks[i]; // start with copy of PK
        EXPECT(secp256k1_ec_pubkey_tweak_mul(ctx, &rPK, r), "Failed to compute r*PK (tweak mul)");

        // c. Add them: C2 = mG + rPK
        const secp256k1_pubkey *summands[2];
        summands[0] = &mG;
        summands[1] = &rPK;
        EXPECT(secp256k1_ec_pubkey_combine(ctx, &C2s[i], summands, 2), "Failed to combine mG + rPK");
    }

    // 3. Generate Proof
    unsigned char proof[1024];

    // Passing flat arrays 'C2s' and 'pks' directly.
    int res = secp256k1_mpt_prove_equality_shared_r(
            ctx, proof,
            amount,          // correct arg order
            r,
            N_RECIPIENTS,
            &C1,
            C2s,             // Pass the array directly
            pks,             // Pass the array directly
            tx_context
    );

    EXPECT(res == 1, "Proof Generation Function returned failure");
    printf("Proof generated successfully.\n");

    // 4. Verify Proof
    res = secp256k1_mpt_verify_equality_shared_r(
            ctx, proof,
            N_RECIPIENTS,
            &C1,
            C2s,            // Pass the array directly
            pks,            // Pass the array directly
            tx_context
    );

    EXPECT(res == 1, "Proof Verification Function returned failure");
    printf("Proof verified successfully.\n");

    printf("Test passed!\n");
    secp256k1_context_destroy(ctx);
    return 0;
}
