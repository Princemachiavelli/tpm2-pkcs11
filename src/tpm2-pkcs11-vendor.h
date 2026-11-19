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

/*
 * CKM_TPM2_AK_PAIR_GEN: C_GenerateKeyPair of an attestation key: a restricted ECDSA signing key
 * that never leaves the TPM (fixedTPM, fixedParent), an ordinary key pair of the token otherwise.
 * It signs nothing but statements the TPM itself makes, such as CKM_TPM2_CERTIFY_OBJECT's.
 *
 *   pMechanism  no parameter.
 *   public key template   CKA_EC_PARAMS: NIST P-256, P-384 or P-521; the ECDSA hash is the
 *                         curve's (SHA-256, SHA-384, SHA-512). CKA_TOKEN is true.
 *   Neither template may set CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT, CKA_EXTRACTABLE
 *   or CKA_SENSITIVE other than as the key is (CKR_TEMPLATE_INCONSISTENT).
 *
 * The private key has CKA_SIGN false and no CKA_ALLOWED_MECHANISMS, so C_SignInit refuses it
 * in the module; CKA_KEY_GEN_MECHANISM is CKM_TPM2_AK_PAIR_GEN. That it is restricted can be
 * read in the TPMA_OBJECT of its CKA_TPM2_PUB_BLOB.
 */
#define CKM_TPM2_AK_PAIR_GEN     (CKM_VENDOR_DEFINED|CKM_VENDOR_TPM2_DEFINED|0x2UL)

/*
 * CKM_TPM2_CERTIFY_OBJECT: CKM_TPM2_CERTIFY with an attestation key of the token (a private key
 * made by CKM_TPM2_AK_PAIR_GEN) as the signer, named by its object handle, so that a client
 * needs no TPM handle and no TPM access. Used as CKM_TPM2_CERTIFY is (same key to certify,
 * qualifying data and output). A signer that is not such a key is CKR_MECHANISM_PARAM_INVALID.
 *
 * The caller checks the signature under the attestation key's public key (its CKA_EC_POINT,
 * or the CKA_TPM2_PUB_BLOB). The attest names the signer by its qualified Name, which a client
 * cannot compute: the key that signed is identified by its public key only.
 */
#define CKM_TPM2_CERTIFY_OBJECT  (CKM_VENDOR_DEFINED|CKM_VENDOR_TPM2_DEFINED|0x3UL)

typedef struct CK_TPM2_CERTIFY_OBJECT_PARAMS {
    CK_OBJECT_HANDLE hSigner;
} CK_TPM2_CERTIFY_OBJECT_PARAMS;

typedef CK_TPM2_CERTIFY_OBJECT_PARAMS *CK_TPM2_CERTIFY_OBJECT_PARAMS_PTR;

/*
 * CKA_TPM2_EK_PUB_BLOB: on the private key of an attestation key (CKM_TPM2_AK_PAIR_GEN), the public
 * area of the TPM's Endorsement Key that CKM_TPM2_ACTIVATE_CREDENTIAL uses, marshaled as a
 * TPM2B_PUBLIC: the default RSA 2048 EK of the TCG EK Credential Profile (the one the TPM
 * manufacturer's EK certificate is for). A client makes a credential for it with TPM2_MakeCredential
 * (it needs no TPM for that: tpm2_makecredential -T none), naming the attestation key's Name.
 * Absent when the TPM's endorsement hierarchy had an auth value when the key was made. It is a
 * stable identifier of the TPM, so it is on the private object: readable after the user login.
 */
#define CKA_TPM2_EK_PUB_BLOB     (CKA_VENDOR_DEFINED|CKA_VENDOR_TPM2_DEFINED|0x6UL)

/*
 * CKM_TPM2_ACTIVATE_CREDENTIAL: TPM2_ActivateCredential with an attestation key (a private key made
 * by CKM_TPM2_AK_PAIR_GEN) as the key the credential is bound to, and the EK above as the key it is
 * encrypted to. A client uses it to chain the attestation key to the EK certificate: it makes a
 * credential with the EK's public key and the attestation key's Name, and only a TPM that holds
 * both can recover it. For C_DecryptInit / C_Decrypt.
 *
 *   C_DecryptInit hKey       the attestation key's private key object. CKA_ALLOWED_MECHANISMS is
 *                            not consulted (an attestation key has none); any other key is
 *                            CKR_KEY_TYPE_INCONSISTENT.
 *                 pParameter none (CKR_MECHANISM_PARAM_INVALID otherwise).
 *   C_Decrypt     pEncryptedData the TPM2B_ID_OBJECT (the credential blob) followed by the
 *                            TPM2B_ENCRYPTED_SECRET (the secret), as TPM2_MakeCredential returns
 *                            them, marshaled and concatenated: without the file header that
 *                            tpm2_makecredential writes (CKR_ENCRYPTED_DATA_INVALID if they do not
 *                            parse to the end, or the TPM refuses them: a credential made for
 *                            another key or Name).
 *                 pData      the credential: at most 32 bytes, the digest size of the EK's name
 *                            algorithm, which TPM2_MakeCredential enforces. The buffer must hold
 *                            CK_TPM2_ACTIVATE_CREDENTIAL_MAX_LEN bytes (a call with a NULL pData
 *                            returns that length without touching the TPM), which is a bound,
 *                            not the length. As with any decryption, a buffer too small keeps
 *                            the operation; any other error ends it.
 *
 * The Endorsement Key is created from the endorsement hierarchy and flushed inside the operation:
 * the module needs the endorsement hierarchy's auth value to be empty, as on a TPM that has not
 * been taken (CKR_GENERAL_ERROR otherwise). The user must be logged in.
 */
#define CKM_TPM2_ACTIVATE_CREDENTIAL (CKM_VENDOR_DEFINED|CKM_VENDOR_TPM2_DEFINED|0x4UL)

/* An upper bound of the credential CKM_TPM2_ACTIVATE_CREDENTIAL returns (sizeof(TPMU_HA)). */
#define CK_TPM2_ACTIVATE_CREDENTIAL_MAX_LEN 64UL

/* The longest input of CKM_TPM2_ACTIVATE_CREDENTIAL accepted (an id object and an RSA 2048 secret are about 400). */
#define CK_TPM2_ACTIVATE_CREDENTIAL_MAX_INPUT_LEN 1024UL

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
