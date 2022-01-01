

#ifndef _ECDH_H__
#define _ECDH_H__


/* for size-annotated integer types: uint8_t, uint32_t etc. */
#include <stdint.h> 

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define NIST_B163  1
#define NIST_K163  2
#define NIST_B233  3
#define NIST_K233  4
#define NIST_B283  5
#define NIST_K283  6
#define NIST_B409  7
#define NIST_K409  8
#define NIST_B571  9
#define NIST_K571 10

/* What is the default curve to use? */
#ifndef ECC_CURVE
 #define ECC_CURVE NIST_B163
#endif

#if defined(ECC_CURVE) && (ECC_CURVE != 0)
 #if   (ECC_CURVE == NIST_K163) || (ECC_CURVE == NIST_B163)
  #define CURVE_DEGREE       163
  #define ECC_PRV_KEY_SIZE   24
 #elif (ECC_CURVE == NIST_K233) || (ECC_CURVE == NIST_B233)
  #define CURVE_DEGREE       233
  #define ECC_PRV_KEY_SIZE   32
 #elif (ECC_CURVE == NIST_K283) || (ECC_CURVE == NIST_B283)
  #define CURVE_DEGREE       283
  #define ECC_PRV_KEY_SIZE   36
 #elif (ECC_CURVE == NIST_K409) || (ECC_CURVE == NIST_B409)
  #define CURVE_DEGREE       409
  #define ECC_PRV_KEY_SIZE   52
 #elif (ECC_CURVE == NIST_K571) || (ECC_CURVE == NIST_B571)
  #define CURVE_DEGREE       571
  #define ECC_PRV_KEY_SIZE   72
 #endif
#else
 #error Must define a curve to use
#endif

#define ECC_PUB_KEY_SIZE     (2 * ECC_PRV_KEY_SIZE)


/******************************************************************************/


/* NOTE: assumes private is filled with random data before calling */
int ecdh_generate_keys(uint8_t* public_key, uint8_t* private_key);

/* input: own private key + other party's public key, output: shared secret */
int ecdh_shared_secret(const uint8_t* private_key, const uint8_t* others_pub, uint8_t* output);


/* Broken :( .... */
int ecdsa_sign(const uint8_t* private_key, uint8_t* hash, uint8_t* random_k, uint8_t* signature);
int ecdsa_verify(const uint8_t* public_key, uint8_t* hash, const uint8_t* signature);


/******************************************************************************/

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* #ifndef _ECDH_H__ */
