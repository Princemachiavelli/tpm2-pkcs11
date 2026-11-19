/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Vendor-defined PKCS#11 types of tpm2-pkcs11: the attribute and mechanism numbers, and the
 * mechanism parameter structures, that clients may rely on.
 *
 * Include this after a Cryptoki header (pkcs11.h). Everything here is a stable interface: a
 * number or a layout listed here does not change in a release of the same major version.
 *
 * Vendor attributes not listed here (CKA_TPM2_OBJAUTH_ENC, CKA_TPM2_PRIV_BLOB,
 * CKA_TPM2_ENC_BLOB, CKA_TPM2_SERIALIZED_TR) exist in the module's object store, can be
 * returned by C_GetAttributeValue as a side effect, and are NOT stable: do not use them.
 */
#ifndef SRC_TPM2_PKCS11_VENDOR_H_
#define SRC_TPM2_PKCS11_VENDOR_H_

/* The vendor range of tpm2-pkcs11, shared by its attributes and mechanisms. */
#define CKA_VENDOR_TPM2_DEFINED  0x0F000000UL
#define CKM_VENDOR_TPM2_DEFINED  0x0F000000UL

/*
 * CKA_TPM2_PUB_BLOB: the object's TPM public area, marshaled as a TPM2B_PUBLIC (a big-endian
 * 16-bit size, then the TPMT_PUBLIC). Present on every key object that lives in the TPM
 * (public, private and secret keys), readable in any session that can see the object. The
 * object's TPM Name is its name algorithm's identifier followed by that algorithm's digest of
 * the TPMT_PUBLIC (the bytes after the size), so a client can compute it and compare it with
 * what CKM_TPM2_CERTIFY attests.
 */
#define CKA_TPM2_PUB_BLOB        (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x2UL)

/*
 * CKM_TPM2_CERTIFY: TPM2_Certify, with a key of the TPM as the signer, over the key object the
 * operation is initialised with. A vendor mechanism for C_SignInit / C_Sign (or the
 * C_SignUpdate / C_SignFinal form: the parts are concatenated).
 *
 *   C_SignInit   hKey       the key object to certify: a private or secret key in the TPM.
 *                           CKA_SIGN and CKA_ALLOWED_MECHANISMS are not consulted: the
 *                           mechanism signs nothing the key holder chose, and certifies keys
 *                           that can sign nothing (decrypt-only, derive-only, HMAC).
 *                pParameter CK_TPM2_CERTIFY_PARAMS.
 *   C_Sign       pData      the qualifying data: a caller-chosen nonce of 0 to 64 bytes, signed
 *                           into the statement (CKR_DATA_LEN_RANGE above that).
 *                pSignature TPM2B_ATTEST || TPMT_SIGNATURE, each as the TPM marshals it. The
 *                           buffer must hold CK_TPM2_CERTIFY_MAX_LEN bytes (a call with a NULL
 *                           pSignature returns that length without touching the TPM);
 *                           *pulSignatureLen is the length of what was written.
 *
 * The signature is the signer's own scheme (TPMT_SIG_SCHEME TPM2_ALG_NULL: a signing key with
 * a scheme in its template uses it). The user must be logged in, as for any use of a key.
 *
 * The caller verifies everything: that the signature verifies under the signer's public key,
 * that extraData is the nonce it sent, that the attested name is the Name of CKA_TPM2_PUB_BLOB
 * and the qualified signer the signer's.
 */
#define CKM_TPM2_CERTIFY         (CKM_VENDOR_DEFINED|CKM_VENDOR_TPM2_DEFINED|0x1UL)

/* An upper bound of the output of CKM_TPM2_CERTIFY (an attest of a certified key and a 4096-bit RSA signature). */
#define CK_TPM2_CERTIFY_MAX_LEN  1024UL

/* The longest qualifying data CKM_TPM2_CERTIFY takes (sizeof(TPM2B_DATA.buffer)). */
#define CK_TPM2_CERTIFY_MAX_QUALIFYING_LEN 64UL

typedef struct CK_TPM2_CERTIFY_PARAMS {
    /*
     * The persistent TPM handle of the signing key (0x81000000 to 0x81FFFFFF): a key the caller
     * made, with an empty auth value and a signing capability (a restricted signing key, an
     * attestation key, is the intended signer). The module only uses it.
     */
    CK_ULONG ulSignerHandle;
} CK_TPM2_CERTIFY_PARAMS;

typedef CK_TPM2_CERTIFY_PARAMS *CK_TPM2_CERTIFY_PARAMS_PTR;

#endif /* SRC_TPM2_PKCS11_VENDOR_H_ */
