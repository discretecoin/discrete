// SPDX-License-Identifier: MIT

#include <stdlib.h>

#include <oqs/kem_ml_kem.h>

#if defined(OQS_ENABLE_KEM_ml_kem_768)

OQS_KEM *OQS_KEM_ml_kem_768_new(void) {

	OQS_KEM *kem = OQS_MEM_malloc(sizeof(OQS_KEM));
	if (kem == NULL) {
		return NULL;
	}
	kem->method_name = OQS_KEM_alg_ml_kem_768;
	kem->alg_version = "FIPS203";

	kem->claimed_nist_level = 3;
	kem->ind_cca = true;

	kem->length_public_key = OQS_KEM_ml_kem_768_length_public_key;
	kem->length_secret_key = OQS_KEM_ml_kem_768_length_secret_key;
	kem->length_ciphertext = OQS_KEM_ml_kem_768_length_ciphertext;
	kem->length_shared_secret = OQS_KEM_ml_kem_768_length_shared_secret;
	kem->length_keypair_seed = OQS_KEM_ml_kem_768_length_keypair_seed;

	kem->keypair = OQS_KEM_ml_kem_768_keypair;
	kem->keypair_derand = OQS_KEM_ml_kem_768_keypair_derand;
	kem->encaps = OQS_KEM_ml_kem_768_encaps;
	kem->decaps = OQS_KEM_ml_kem_768_decaps;

	return kem;
}

extern int PQCP_MLKEM_NATIVE_MLKEM768_C_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_C_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int PQCP_MLKEM_NATIVE_MLKEM768_C_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_C_enc_derand(uint8_t *ct, uint8_t *ss, const uint8_t *pk, const uint8_t *coins);
extern int PQCP_MLKEM_NATIVE_MLKEM768_C_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);

#if defined(OQS_ENABLE_KEM_ml_kem_768_x86_64)
extern int PQCP_MLKEM_NATIVE_MLKEM768_X86_64_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_X86_64_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int PQCP_MLKEM_NATIVE_MLKEM768_X86_64_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_X86_64_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

#if defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
extern int PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_keypair(uint8_t *pk, uint8_t *sk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_keypair_derand(uint8_t *pk, uint8_t *sk, const uint8_t *seed);
extern int PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif

#if defined(OQS_USE_CUPQC)
#if defined(OQS_ENABLE_KEM_ml_kem_768_cuda)
extern int cupqc_ml_kem_768_keypair(uint8_t *pk, uint8_t *sk);
extern int cupqc_ml_kem_768_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
extern int cupqc_ml_kem_768_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
#endif
#endif /* OQS_USE_CUPQC */

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_keypair_derand(uint8_t *public_key, uint8_t *secret_key, const uint8_t *seed) {
#if defined(OQS_ENABLE_KEM_ml_kem_768_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_X86_64_keypair_derand(public_key, secret_key, seed);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair_derand(public_key, secret_key, seed);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_keypair_derand(public_key, secret_key, seed);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair_derand(public_key, secret_key, seed);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_ml_kem_768_cuda)
	return (OQS_STATUS) PQCLEAN_MLKEM768_CUDA_crypto_kem_keypair_derand(public_key, secret_key, seed);
#else
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair_derand(public_key, secret_key, seed);
#endif
}

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_keypair(uint8_t *public_key, uint8_t *secret_key) {
#if defined(OQS_USE_CUPQC) && defined(OQS_ENABLE_KEM_ml_kem_768_cuda)
	return (OQS_STATUS) cupqc_ml_kem_768_keypair(public_key, secret_key);
#endif /* OQS_USE_CUPQC && OQS_ENABLE_KEM_ml_kem_768_cuda */
#if defined(OQS_ENABLE_KEM_ml_kem_768_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_X86_64_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_keypair(public_key, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair(public_key, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_keypair(public_key, secret_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_encaps(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key) {
#if defined(OQS_USE_CUPQC) && defined(OQS_ENABLE_KEM_ml_kem_768_cuda)
	return (OQS_STATUS) cupqc_ml_kem_768_enc(ciphertext, shared_secret, public_key);
#endif /* OQS_USE_CUPQC && OQS_ENABLE_KEM_ml_kem_768_cuda */
#if defined(OQS_ENABLE_KEM_ml_kem_768_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_X86_64_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_enc(ciphertext, shared_secret, public_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_enc(ciphertext, shared_secret, public_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_enc(ciphertext, shared_secret, public_key);
#endif
}

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_encaps_derand(uint8_t *ciphertext, uint8_t *shared_secret, const uint8_t *public_key, const uint8_t *coins) {
	/*
	 * mlkem-native exposes this operation from every backend, but it is not
	 * part of upstream liboqs's dispatch API. Deliberately use the always-built
	 * portable backend here: this keeps the application-facing symbol stable
	 * across x86_64/aarch64 configurations and preserves that backend's FIPS 203
	 * public-key modulus check. The call is fully reentrant and does not touch
	 * OQS's process-global randombytes provider.
	 */
	OQS_STATUS rc = (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_enc_derand(ciphertext, shared_secret, public_key, coins);
	if (rc != OQS_SUCCESS) {
		/* Never expose partial backend output on a non-canonical public key. */
		OQS_MEM_cleanse(ciphertext, OQS_KEM_ml_kem_768_length_ciphertext);
		OQS_MEM_cleanse(shared_secret, OQS_KEM_ml_kem_768_length_shared_secret);
	}
	return rc;
}

OQS_API OQS_STATUS OQS_KEM_ml_kem_768_decaps(uint8_t *shared_secret, const uint8_t *ciphertext, const uint8_t *secret_key) {
#if defined(OQS_USE_CUPQC) && defined(OQS_ENABLE_KEM_ml_kem_768_cuda)
	return (OQS_STATUS) cupqc_ml_kem_768_dec(shared_secret, ciphertext, secret_key);
#endif /* OQS_USE_CUPQC && OQS_ENABLE_KEM_ml_kem_768_cuda */
#if defined(OQS_ENABLE_KEM_ml_kem_768_x86_64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_AVX2) && OQS_CPU_has_extension(OQS_CPU_EXT_BMI2) && OQS_CPU_has_extension(OQS_CPU_EXT_POPCNT)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_X86_64_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#elif defined(OQS_ENABLE_KEM_ml_kem_768_aarch64)
#if defined(OQS_DIST_BUILD)
	if (OQS_CPU_has_extension(OQS_CPU_EXT_ARM_NEON)) {
#endif /* OQS_DIST_BUILD */
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_AARCH64_dec(shared_secret, ciphertext, secret_key);
#if defined(OQS_DIST_BUILD)
	} else {
		return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_dec(shared_secret, ciphertext, secret_key);
	}
#endif /* OQS_DIST_BUILD */
#else
	return (OQS_STATUS) PQCP_MLKEM_NATIVE_MLKEM768_C_dec(shared_secret, ciphertext, secret_key);
#endif
}

#endif
