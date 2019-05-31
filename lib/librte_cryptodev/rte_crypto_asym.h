/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2018 Cavium Networks
 */

#ifndef _RTE_CRYPTO_ASYM_H_
#define _RTE_CRYPTO_ASYM_H_

/**
 * @file rte_crypto_asym.h
 *
 * RTE Definitions for Asymmetric Cryptography
 *
 * Defines asymmetric algorithms and modes, as well as supported
 * asymmetric crypto operations.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <string.h>
#include <stdint.h>

#include <rte_memory.h>
#include <rte_mempool.h>
#include <rte_common.h>

#include "rte_crypto_sym.h"

typedef struct rte_crypto_param_t {
	uint8_t *data;
	/**< pointer to buffer holding data */
	rte_iova_t iova;
	/**< IO address of data buffer */
	size_t length;
	/**< length of data in bytes */
} rte_crypto_param;

/** asym xform type name strings */
extern const char *
rte_crypto_asym_xform_strings[];

/** asym operations type name strings */
extern const char *
rte_crypto_asym_op_strings[];

/**
 * Asymmetric crypto transformation types.
 * Each xform type maps to one asymmetric algorithm
 * performing specific operation
 *
 */
enum rte_crypto_asym_xform_type {
	RTE_CRYPTO_ASYM_XFORM_UNSPECIFIED = 0,
	/**< Invalid xform. */
	RTE_CRYPTO_ASYM_XFORM_NONE,
	/**< Xform type None.
	 * May be supported by PMD to support
	 * passthrough op for debugging purpose.
	 * if xform_type none , op_type is disregarded.
	 */
	RTE_CRYPTO_ASYM_XFORM_RSA,
	/**< RSA. Performs Encrypt, Decrypt, Sign and Verify.
	 * Refer to rte_crypto_asym_op_type
	 */
	RTE_CRYPTO_ASYM_XFORM_DH,
	/**< Diffie-Hellman.
	 * Performs Key Generate and Shared Secret Compute.
	 * Refer to rte_crypto_asym_op_type
	 */
	RTE_CRYPTO_ASYM_XFORM_DSA,
	/**< Digital Signature Algorithm
	 * Performs Signature Generation and Verification.
	 * Refer to rte_crypto_asym_op_type
	 */
	RTE_CRYPTO_ASYM_XFORM_MODINV,
	/**< Modular Multiplicative Inverse
	 * Perform Modular Multiplicative Inverse b^(-1) mod n
	 */
	RTE_CRYPTO_ASYM_XFORM_MODEX,
	/**< Modular Exponentiation
	 * Perform Modular Exponentiation b^e mod n
	 */
	RTE_CRYPTO_ASYM_XFORM_TYPE_LIST_END
	/**< End of list */
};

/**
 * Asymmetric crypto operation type variants
 */
enum rte_crypto_asym_op_type {
	RTE_CRYPTO_ASYM_OP_ENCRYPT,
	/**< Asymmetric Encrypt operation */
	RTE_CRYPTO_ASYM_OP_DECRYPT,
	/**< Asymmetric Decrypt operation */
	RTE_CRYPTO_ASYM_OP_SIGN,
	/**< Signature Generation operation */
	RTE_CRYPTO_ASYM_OP_VERIFY,
	/**< Signature Verification operation */
	RTE_CRYPTO_ASYM_OP_PRIVATE_KEY_GENERATE,
	/**< DH Private Key generation operation */
	RTE_CRYPTO_ASYM_OP_PUBLIC_KEY_GENERATE,
	/**< DH Public Key generation operation */
	RTE_CRYPTO_ASYM_OP_SHARED_SECRET_COMPUTE,
	/**< DH Shared Secret compute operation */
	RTE_CRYPTO_ASYM_OP_LIST_END
};

/**
 * Padding types for RSA signature.
 */
enum rte_crypto_rsa_padding_type {
	RTE_CRYPTO_RSA_PADDING_NONE = 0,
	/**< RSA no padding scheme.
	 * In this case user is responsible for providing and verification
	 * of padding.
	 * In case RTE_CRYPTO_ASYM_OP_VERIFY op type is used if no
	 * problems in public key 'encryption' detected driver SHALL return
	 * RTE_CRYPTO_OP_STATUS_SUCCESS. But it is USER RESPONSABILITY to
	 * remove padding and verify signature.
	 */
	RTE_CRYPTO_RSA_PADDING_PKCS1,
	/**< RSA PKCS#1 PKCS1-v1_5 padding scheme. For signatures block type 01,
	 * for encryption block type 02 are used.
	 *
	 * In case RTE_CRYPTO_ASYM_OP_VERIFY op type is used crypto op status
	 * is set to RTE_CRYPTO_OP_STATUS_SUCCESS when signature is properly
	 * verified, RTE_CRYPTO_OP_STATUS_ERROR when it failed.
	 */
	RTE_CRYPTO_RSA_PADDING_OAEP,
	/**< RSA PKCS#1 OAEP padding scheme, can be used only for encryption/
	 * decryption.
	 */
	RTE_CRYPTO_RSA_PADDING_PSS,
	/**< RSA PKCS#1 PSS padding scheme, can be used only for signatures.
	 *
	 * Crypto op status is set to RTE_CRYPTO_OP_STATUS_SUCCESS
	 * when signature is properly verified, RTE_CRYPTO_OP_STATUS_ERROR
	 * when it failed.
	 */
	RTE_CRYPTO_RSA_PADDING_TYPE_LIST_END
};

/**
 * RSA private key type enumeration
 *
 * enumerates private key format required to perform RSA crypto
 * transform.
 *
 */
enum rte_crypto_rsa_priv_key_type {
	RTE_RSA_KEY_TYPE_EXP,
	/**< RSA private key is an exponent */
	RTE_RSA_KET_TYPE_QT,
	/**< RSA private key is in quintuple format
	 * See rte_crypto_rsa_priv_key_qt
	 */
};

/**
 * Structure describing RSA private key in quintuple format.
 * See PKCS V1.5 RSA Cryptography Standard.
 */
struct rte_crypto_rsa_priv_key_qt {
	rte_crypto_param p;
	/**< p - Private key component P
	 * Private key component of RSA parameter  required for CRT method
	 * of private key operations in Octet-string network byte order
	 * format.
	 */

	rte_crypto_param q;
	/**< q - Private key component Q
	 * Private key component of RSA parameter  required for CRT method
	 * of private key operations in Octet-string network byte order
	 * format.
	 */

	rte_crypto_param dP;
	/**< dP - Private CRT component
	 * Private CRT component of RSA parameter  required for CRT method
	 * RSA private key operations in Octet-string network byte order
	 * format.
	 * dP = d mod ( p - 1 )
	 */

	rte_crypto_param dQ;
	/**< dQ - Private CRT component
	 * Private CRT component of RSA parameter  required for CRT method
	 * RSA private key operations in Octet-string network byte order
	 * format.
	 * dQ = d mod ( q - 1 )
	 */

	rte_crypto_param qInv;
	/**< qInv - Private CRT component
	 * Private CRT component of RSA parameter  required for CRT method
	 * RSA private key operations in Octet-string network byte order
	 * format.
	 * qInv = inv q mod p
	 */
};

/**
 * Asymmetric RSA transform data
 *
 * Structure describing RSA xform params
 *
 */
struct rte_crypto_rsa_xform {
	rte_crypto_param n;
	/**< n - Modulus
	 * Modulus data of RSA operation in Octet-string network
	 * byte order format.
	 */

	rte_crypto_param e;
	/**< e - Public key exponent
	 * Public key exponent used for RSA public key operations in Octet-
	 * string network byte order format.
	 */

	enum rte_crypto_rsa_priv_key_type key_type;

	__extension__
	union {
		rte_crypto_param d;
		/**< d - Private key exponent
		 * Private key exponent used for RSA
		 * private key operations in
		 * Octet-string  network byte order format.
		 */

		struct rte_crypto_rsa_priv_key_qt qt;
		/**< qt - Private key in quintuple format */
	};
};

/**
 * Asymmetric Modular exponentiation transform data
 *
 * Structure describing modular exponentiation xform param
 *
 */
struct rte_crypto_modex_xform {
	rte_crypto_param modulus;
	/**< modulus
	 * Pointer to the modulus data for modexp transform operation
	 * in octet-string network byte order format
	 *
	 * In case this number is equal to zero the driver shall set
	 * the crypto op status field to RTE_CRYPTO_OP_STATUS_ERROR
	 */

	rte_crypto_param exponent;
	/**< exponent
	 * Exponent of the modexp transform operation in
	 * octet-string network byte order format
	 */
};

/**
 * Asymmetric modular multiplicative inverse transform operation
 *
 * Structure describing modular multiplicative inverse transform
 *
 */
struct rte_crypto_modinv_xform {
	rte_crypto_param modulus;
	/**<
	 * Pointer to the modulus data for modular multiplicative inverse
	 * operation in octet-string network byte order format
	 *
	 * In case this number is equal to zero the driver shall set
	 * the crypto op status field to RTE_CRYPTO_OP_STATUS_ERROR
	 *
	 * This number shall be relatively prime to base
	 * in corresponding Modular Multiplicative Inverse
	 * rte_crypto_mod_op_param
	 */
};

/**
 * Asymmetric DH transform data
 *
 * Structure describing deffie-hellman xform params
 *
 */
struct rte_crypto_dh_xform {
	enum rte_crypto_asym_op_type type;
	/**< Setup xform for key generate or shared secret compute */

	rte_crypto_param p;
	/**< p : Prime modulus data
	 * DH prime modulus data in octet-string network byte order format.
	 *
	 */

	rte_crypto_param g;
	/**< g : Generator
	 * DH group generator data in octet-string network byte order
	 * format.
	 *
	 */
};

/**
 * Asymmetric Digital Signature transform operation
 *
 * Structure describing DSA xform params
 *
 */
struct rte_crypto_dsa_xform {
	rte_crypto_param p;
	/**< p - Prime modulus
	 * Prime modulus data for DSA operation in Octet-string network byte
	 * order format.
	 */
	rte_crypto_param q;
	/**< q : Order of the subgroup.
	 * Order of the subgroup data in Octet-string network byte order
	 * format.
	 * (p-1) % q = 0
	 */
	rte_crypto_param g;
	/**< g: Generator of the subgroup
	 * Generator  data in Octet-string network byte order format.
	 */
	rte_crypto_param x;
	/**< x: Private key of the signer in octet-string network
	 * byte order format.
	 * Used when app has pre-defined private key.
	 * Valid only when xform chain is DSA ONLY.
	 * if xform chain is DH private key generate + DSA, then DSA sign
	 * compute will use internally generated key.
	 */
};

/**
 * Operations params for modular operations:
 * exponentiation and multiplicative inverse
 *
 */
struct rte_crypto_mod_op_param {
	rte_crypto_param base;
	/**<
	 * Pointer to base of modular exponentiation/multiplicative
	 * inverse data in octet-string network byte order format
	 *
	 * In case Multiplicative Inverse is used this number shall
	 * be relatively prime to modulus in corresponding Modular
	 * Multiplicative Inverse rte_crypto_modinv_xform
	 */

	rte_crypto_param result;
	/**<
	 * Pointer to the result of modular exponentiation/multiplicative inverse
	 * data in octet-string network byte order format.
	 *
	 * This field shall be big enough to hold the result of Modular
	 * Exponentiation or Modular Multiplicative Inverse
	 * (bigger or equal to length of modulus)
	 */
};

/**
 * Asymmetric crypto transform data
 *
 * Structure describing asym xforms.
 */
struct rte_crypto_asym_xform {
	struct rte_crypto_asym_xform *next;
	/**< Pointer to next xform to set up xform chain.*/
	enum rte_crypto_asym_xform_type xform_type;
	/**< Asymmetric crypto transform */

	__extension__
	union {
		struct rte_crypto_rsa_xform rsa;
		/**< RSA xform parameters */

		struct rte_crypto_modex_xform modex;
		/**< Modular Exponentiation xform parameters */

		struct rte_crypto_modinv_xform modinv;
		/**< Modular Multiplicative Inverse xform parameters */

		struct rte_crypto_dh_xform dh;
		/**< DH xform parameters */

		struct rte_crypto_dsa_xform dsa;
		/**< DSA xform parameters */
	};
};

struct rte_cryptodev_asym_session;

/**
 * RSA operation params
 *
 */
struct rte_crypto_rsa_op_param {
	enum rte_crypto_asym_op_type op_type;
	/**< Type of RSA operation for transform */;

	rte_crypto_param message;
	/**<
	 * Pointer to data
	 * - to be encrypted for RSA public encrypt.
	 * - to be signed for RSA sign generation.
	 * - to be authenticated for RSA sign verification.
	 */

	rte_crypto_param cipher;
	/**<
	 * Pointer to data
	 * - to be decrypted for RSA private decrypt.
	 *
	 * When RTE_CRYPTO_ASYM_OP_ENCRYPT op_type used size in bytes
	 * of this field need to be equal to the size of corresponding
	 * RSA key. Returned data is in Big-Endian format which means
	 * that Least-Significant byte will be placed at top byte of an array
	 * (at message.data[message.length - 1]), cipher.length SHALL
	 * therefore remain unchanged.
	 */

	rte_crypto_param sign;
	/**<
	 * Pointer to RSA signature data. If operation is RSA
	 * sign @ref RTE_CRYPTO_ASYM_OP_SIGN, buffer will be
	 * over-written with generated signature.
	 *
	 * Length of the signature data will be equal to the
	 * RSA prime modulus length.
	 *
	 * Returned data is in Big-Endian format which means
	 * that Least-Significant byte will be placed at top byte of an array
	 * (at message.data[message.length - 1]), sign.length SHALL
	 * therefore remain unchanged.
	 */

	struct {
		enum rte_crypto_rsa_padding_type type;
		/**<
		 * In case RTE_CRYPTO_RSA_PADDING_PKCS1 is selected,
		 * driver will distinguish between block type basing
		 * on rte_crypto_asym_op_type of the operation.
		 *
		 * Which padding type is supported by the driver SHALL be
		 * available in in specific driver guide or capabilities.
		 */
		enum rte_crypto_auth_algorithm hash;
		/**<
		 * -	For PKCS1-v1_5 signature (Block type 01) this field
		 * represents hash function that will be used to create
		 * message hash. This hash will be then concatenated with
		 * hash algorithm identifier into DER encoded sequence.
		 * If RTE_CRYPTO_HASH_INVALID is set, driver default will be set.
		 * If RTE_CRYPTO_HASH_NONE is set, message will be signed as it is.
		 *
		 * -	For OAEP this field represents hash function that will
		 * be used to produce hash of the optional label.
		 * If RTE_CRYPTO_HASH_INVALID or RTE_CRYPTO_HASH_NONE is set
		 * driver will use default value. For OAEP usually it is SHA-1.
		 *
		 * -	For PSS this field represents hash function that will be used
		 * to produce hash (mHash) of message M and of M' (padding1 | mHash | salt)
		 * If RTE_CRYPTO_HASH_INVALID or RTE_CRYPTO_HASH_NONE is set
		 * driver will use default value.
		 *
		 * -	If driver supports only one function RTE_CRYPTO_HASH_NONE
		 * according to aformentioned restrictions should be used or
		 * specific function should be set, otherwise on dequeue the driver
		 * SHALL set crypto_op_status to RTE_CRYPTO_OP_STATUS_INVALID_ARGS.
		 */
		union {
			struct {
				enum rte_crypto_auth_algorithm mgf;
				/**<
				 * Mask genereation function hash algorithm.
				 * If this field is not supported by the driver,
				 * it should be set to RTE_CRYPTO_HASH_NONE.
				 */
				rte_crypto_param label;
				/**<
				 * Optional label, if driver does not support
				 * this option, optional label is just an empty string.
				 */
			} OAEP;
			struct {
				enum rte_crypto_auth_algorithm mgf;
				/**<
				 * Mask genereation function hash algorithm.
				 * If this field is not supported by the driver,
				 * it should be set to RTE_CRYPTO_HASH_NONE.
				 */
				int seed_len;
				/**<
				 * Intended seed length. Nagative number has special
				 * value as follows:
				 * -1 : seed len = length of output ot used hash function
				 * -2 : seed len is maximized
				 */
			} PSS;
		};
	} padding;
	/**<
	 * Padding type of RSA crypto operation.
	 * What are random number generator requirements and prequisites
	 * SHALL be put in specific driver guide
	 */
};

/**
 * Diffie-Hellman Operations params.
 * @note:
 */
struct rte_crypto_dh_op_param {
	rte_crypto_param pub_key;
	/**<
	 * Output generated public key when xform type is
	 * DH PUB_KEY_GENERATION.
	 * Input peer public key when xform type is DH
	 * SHARED_SECRET_COMPUTATION
	 * pub_key is in octet-string network byte order format.
	 *
	 */

	rte_crypto_param priv_key;
	/**<
	 * Output generated private key if xform type is
	 * DH PRIVATE_KEY_GENERATION
	 * Input when xform type is DH SHARED_SECRET_COMPUTATION.
	 * priv_key is in octet-string network byte order format.
	 *
	 */

	rte_crypto_param shared_secret;
	/**<
	 * Output with calculated shared secret
	 * when dh xform set up with op type = SHARED_SECRET_COMPUTATION.
	 * shared_secret is an octet-string network byte order format.
	 *
	 */
};

/**
 * DSA Operations params
 *
 */
struct rte_crypto_dsa_op_param {
	enum rte_crypto_asym_op_type op_type;
	/**< Signature Generation or Verification */
	rte_crypto_param message;
	/**< input message to be signed or verified */
	rte_crypto_param r;
	/**< dsa sign component 'r' value
	 *
	 * output if op_type = sign generate,
	 * input if op_type = sign verify
	 */
	rte_crypto_param s;
	/**< dsa sign component 's' value
	 *
	 * output if op_type = sign generate,
	 * input if op_type = sign verify
	 */
	rte_crypto_param y;
	/**< y : Public key of the signer.
	 * Public key data of the signer in Octet-string network byte order
	 * format.
	 * y = g^x mod p
	 */
};

/**
 * Asymmetric Cryptographic Operation.
 *
 * Structure describing asymmetric crypto operation params.
 *
 */
struct rte_crypto_asym_op {
	struct rte_cryptodev_asym_session *session;
	/**< Handle for the initialised session context */

	__extension__
	union {
		struct rte_crypto_rsa_op_param rsa;
		struct rte_crypto_mod_op_param modex;
		struct rte_crypto_mod_op_param modinv;
		struct rte_crypto_dh_op_param dh;
		struct rte_crypto_dsa_op_param dsa;
	};
};

#ifdef __cplusplus
}
#endif

#endif /* _RTE_CRYPTO_ASYM_H_ */
