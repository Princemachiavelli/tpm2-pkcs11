/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>

#include <tss2/tss2_mu.h>

#include "test.h"
#include "tpm2-pkcs11-vendor.h"

/*
 * CKM_TPM2_CERTIFY (tpm2-pkcs11-vendor.h): the TPM signs a statement about a key object with a
 * key the caller names. The signer is created by scripts/create_pkcs_store.sh, as a restricted
 * ECDSA P-256 signing key at this persistent handle; its public key is $TPM2_PKCS11_STORE/ak.pem.
 */
#define SIGNER_HANDLE 0x81000F01UL
/* A persistent key of the TPM that is no signing key, also from create_pkcs_store.sh. */
#define NOT_A_SIGNER_HANDLE 0x81000F02UL

struct test_info {
    CK_SESSION_HANDLE handle;
    CK_SLOT_ID slot_id;
};

static int test_setup(void **state) {

    test_info *ti = calloc(1, sizeof(*ti));
    assert_non_null(ti);

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    CK_RV rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, TOKEN_COUNT);

    ti->slot_id = slots[0];

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION, NULL, NULL, &ti->handle);
    assert_int_equal(rv, CKR_OK);

    *state = ti;

    return 0;
}

static int test_teardown(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_RV rv = C_CloseAllSessions(ti->slot_id);
    assert_int_equal(rv, CKR_OK);

    free(ti);

    return 0;
}

static const CK_BYTE nonce[32] = {
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
};

static CK_RV certify_init(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_ULONG signer) {

    CK_TPM2_CERTIFY_PARAMS params = { .ulSignerHandle = signer };
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };

    return C_SignInit(session, &mech, key);
}

static CK_RV certify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_ULONG signer,
        const CK_BYTE *data, CK_ULONG data_len, CK_BYTE *out, CK_ULONG *out_len) {

    CK_RV rv = certify_init(session, key, signer);
    if (rv != CKR_OK) {
        return rv;
    }

    return C_Sign(session, (CK_BYTE_PTR)data, data_len, out, out_len);
}

/* The AK's public key, as the create_pkcs_store.sh wrote it. */
static EVP_PKEY *signer_pkey(void) {

    const char *store = getenv("TPM2_PKCS11_STORE");
    assert_non_null(store);

    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/ak.pem", store);
    assert_true(n > 0 && (size_t)n < sizeof(path));

    FILE *f = fopen(path, "r");
    assert_non_null(f);
    EVP_PKEY *pkey = PEM_read_PUBKEY(f, NULL, NULL, NULL);
    fclose(f);
    assert_non_null(pkey);

    return pkey;
}

/*
 * Everything a client checks of a CKM_TPM2_CERTIFY statement: the statement parses to the end,
 * is a certify statement of this nonce, names the object by the Name of its CKA_TPM2_PUB_BLOB,
 * and carries the signer's valid signature.
 */
static void check_statement(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
        const CK_BYTE *data, CK_ULONG data_len, const CK_BYTE *out, CK_ULONG out_len) {

    CK_BYTE pub_blob[1024];
    CK_ATTRIBUTE pub_attr = { CKA_TPM2_PUB_BLOB, pub_blob, sizeof(pub_blob) };
    CK_RV rv = C_GetAttributeValue(session, key, &pub_attr, 1);
    assert_int_equal(rv, CKR_OK);
    /* a TPM2B_PUBLIC: its size, then the TPMT_PUBLIC the Name is made of */
    assert_true(pub_attr.ulValueLen > 2);
    assert_int_equal(pub_attr.ulValueLen, 2 + ((pub_blob[0] << 8) | pub_blob[1]));

    TPM2B_ATTEST attest2b = { 0 };
    TPMT_SIGNATURE signature = { 0 };
    size_t off = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_ATTEST_Unmarshal(out, out_len, &off, &attest2b);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    rc = Tss2_MU_TPMT_SIGNATURE_Unmarshal(out, out_len, &off, &signature);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(off, out_len);

    TPMS_ATTEST attest = { 0 };
    size_t attest_off = 0;
    rc = Tss2_MU_TPMS_ATTEST_Unmarshal(attest2b.attestationData, attest2b.size, &attest_off, &attest);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(attest_off, attest2b.size);

    assert_int_equal(attest.magic, TPM2_GENERATED_VALUE);
    assert_int_equal(attest.type, TPM2_ST_ATTEST_CERTIFY);
    assert_int_equal(attest.extraData.size, data_len);
    assert_memory_equal(attest.extraData.buffer, data, data_len);

    /* the Name: the name algorithm, then its digest of the TPMT_PUBLIC (SHA-256 for tpm2_ptool's keys) */
    const TPM2B_NAME *name = &attest.attested.certify.name;
    assert_int_equal(name->size, 2 + SHA256_DIGEST_LENGTH);
    assert_int_equal((name->name[0] << 8) | name->name[1], TPM2_ALG_SHA256);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(&pub_blob[2], pub_attr.ulValueLen - 2, digest);
    assert_memory_equal(&name->name[2], digest, sizeof(digest));

    /* the signer's signature over the statement exactly as the TPM marshaled it */
    assert_int_equal(signature.sigAlg, TPM2_ALG_ECDSA);
    assert_int_equal(signature.signature.ecdsa.hash, TPM2_ALG_SHA256);
    ECDSA_SIG *ecdsa = ECDSA_SIG_new();
    assert_non_null(ecdsa);
    BIGNUM *r = BN_bin2bn(signature.signature.ecdsa.signatureR.buffer, signature.signature.ecdsa.signatureR.size, NULL);
    BIGNUM *s = BN_bin2bn(signature.signature.ecdsa.signatureS.buffer, signature.signature.ecdsa.signatureS.size, NULL);
    assert_non_null(r);
    assert_non_null(s);
    assert_int_equal(ECDSA_SIG_set0(ecdsa, r, s), 1);
    unsigned char *der = NULL;
    int der_len = i2d_ECDSA_SIG(ecdsa, &der);
    ECDSA_SIG_free(ecdsa);
    assert_true(der_len > 0);

    EVP_PKEY *pkey = signer_pkey();
    EVP_MD_CTX *md = EVP_MD_CTX_new();
    assert_non_null(md);
    assert_int_equal(EVP_DigestVerifyInit(md, NULL, EVP_sha256(), NULL, pkey), 1);
    int ok = EVP_DigestVerify(md, der, der_len, attest2b.attestationData, attest2b.size);
    assert_int_equal(ok, 1);
    EVP_MD_CTX_free(md);
    EVP_PKEY_free(pkey);
    OPENSSL_free(der);
}

static void certify_and_check(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key) {

    CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
    CK_ULONG out_len = sizeof(out);
    CK_RV rv = certify(session, key, SIGNER_HANDLE, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_OK);
    assert_true(out_len < sizeof(out));

    check_statement(session, key, nonce, sizeof(nonce), out, out_len);
}

/* The mechanism is listed, and is a signing mechanism of the TPM. */
static void test_certify_is_listed(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_MECHANISM_TYPE mechs[256];
    CK_ULONG count = ARRAY_LEN(mechs);
    CK_RV rv = C_GetMechanismList(ti->slot_id, mechs, &count);
    assert_int_equal(rv, CKR_OK);

    bool found = false;
    for (CK_ULONG i = 0; i < count; i++) {
        found |= mechs[i] == CKM_TPM2_CERTIFY;
    }
    assert_true(found);

    CK_MECHANISM_INFO info;
    rv = C_GetMechanismInfo(ti->slot_id, CKM_TPM2_CERTIFY, &info);
    assert_int_equal(rv, CKR_OK);
    assert_true(info.flags & CKF_SIGN);
    assert_true(info.flags & CKF_HW);
}

/* Private keys of each type are certified, and the statements verify. */
static void test_certify_private_keys(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_KEY_TYPE types[] = { CKK_EC, CKK_RSA };
    for (size_t i = 0; i < ARRAY_LEN(types); i++) {
        CK_OBJECT_HANDLE pub, priv;
        get_keypair(session, types[i], &pub, &priv);
        certify_and_check(session, priv);
    }
}

/*
 * Secret keys are certified too (the AES and HMAC keys of the token), though none of them lists
 * CKM_TPM2_CERTIFY in its CKA_ALLOWED_MECHANISMS.
 */
static void test_certify_secret_keys(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_BBOOL always_authenticate = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_ALWAYS_AUTHENTICATE, &always_authenticate, sizeof(always_authenticate) },
    };
    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE keys[16];
    CK_ULONG count = 0;
    rv = C_FindObjects(session, keys, ARRAY_LEN(keys), &count);
    assert_int_equal(rv, CKR_OK);
    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);
    /* 2 AES keys and the HMAC key */
    assert_true(count >= 3);

    for (CK_ULONG i = 0; i < count; i++) {
        certify_and_check(session, keys[i]);
    }
}

/* A key that needs a context login for every use needs it to be certified. */
static void test_certify_always_authenticate(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_OBJECT_CLASS key_class = CKO_PRIVATE_KEY;
    CK_BBOOL always_authenticate = CK_TRUE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &key_class, sizeof(key_class) },
        { CKA_ALWAYS_AUTHENTICATE, &always_authenticate, sizeof(always_authenticate) },
    };
    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);

    CK_OBJECT_HANDLE key;
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &key, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);
    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    rv = certify_init(session, key, SIGNER_HANDLE);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
    CK_ULONG out_len = sizeof(out);
    rv = C_Sign(session, (CK_BYTE_PTR)nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);

    context_login(session);

    out_len = sizeof(out);
    rv = C_Sign(session, (CK_BYTE_PTR)nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_statement(session, key, nonce, sizeof(nonce), out, out_len);
}

/*
 * The output length is an upper bound the caller learns without the TPM being used, the buffer
 * must be that long, and the part form of the operation certifies as C_Sign does.
 */
static void test_certify_sizes_and_parts(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_OBJECT_HANDLE pub, priv;
    get_keypair(session, CKK_EC, &pub, &priv);

    CK_RV rv = certify_init(session, priv, SIGNER_HANDLE);
    assert_int_equal(rv, CKR_OK);

    CK_ULONG out_len = 0;
    rv = C_Sign(session, (CK_BYTE_PTR)nonce, sizeof(nonce), NULL, &out_len);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(out_len, CK_TPM2_CERTIFY_MAX_LEN);

    /* a buffer shorter than the bound is refused, keeping the operation */
    CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
    out_len = CK_TPM2_CERTIFY_MAX_LEN - 1;
    rv = C_Sign(session, (CK_BYTE_PTR)nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_BUFFER_TOO_SMALL);
    assert_int_equal(out_len, CK_TPM2_CERTIFY_MAX_LEN);

    /* the same operation, in two parts of the nonce */
    rv = C_SignUpdate(session, (CK_BYTE_PTR)nonce, 10);
    assert_int_equal(rv, CKR_OK);
    rv = C_SignUpdate(session, (CK_BYTE_PTR)&nonce[10], sizeof(nonce) - 10);
    assert_int_equal(rv, CKR_OK);
    out_len = sizeof(out);
    rv = C_SignFinal(session, out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_statement(session, priv, nonce, sizeof(nonce), out, out_len);

    /* a nonce of the longest length, and the operation ends: the next one is not "active" */
    CK_BYTE longest[CK_TPM2_CERTIFY_MAX_QUALIFYING_LEN] = { 0xa5 };
    out_len = sizeof(out);
    rv = certify(session, priv, SIGNER_HANDLE, longest, sizeof(longest), out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_statement(session, priv, longest, sizeof(longest), out, out_len);
}

/*
 * What is refused, each leaving the session fit to certify: a session without the user, the
 * verify operations, a parameter that is not a persistent handle of a signing key, too long a
 * nonce, and an object that is not in the TPM with a private area (a public key).
 */
static void test_certify_refusals(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_OBJECT_HANDLE pub, priv;
    get_keypair(session, CKK_EC, &pub, &priv);

    CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
    CK_ULONG out_len;
    CK_RV rv;

    CK_TPM2_CERTIFY_PARAMS params = { .ulSignerHandle = SIGNER_HANDLE };
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };

    /* it signs; there is nothing to verify */
    rv = C_VerifyInit(session, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    /* the parameter: missing, of another length */
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;
    rv = C_SignInit(session, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params) - 1;
    rv = C_SignInit(session, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* a signer that is no persistent handle, one with no object, one that is no signing key */
    out_len = sizeof(out);
    rv = certify(session, priv, 0x80000001UL, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    rv = certify(session, priv, 0x81000FFEUL, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    out_len = sizeof(out);
    rv = certify(session, priv, NOT_A_SIGNER_HANDLE, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* too long a nonce */
    CK_BYTE too_long[CK_TPM2_CERTIFY_MAX_QUALIFYING_LEN + 1] = { 0 };
    rv = certify(session, priv, SIGNER_HANDLE, too_long, sizeof(too_long), out, &out_len);
    assert_int_equal(rv, CKR_DATA_LEN_RANGE);

    /* a public key object is not in the TPM with a private area */
    rv = certify_init(session, pub, SIGNER_HANDLE);
    assert_int_equal(rv, CKR_KEY_TYPE_INCONSISTENT);

    /* none of it left an operation active */
    certify_and_check(session, priv);

    /* the user must be logged in */
    logout(session);
    rv = certify_init(session, priv, SIGNER_HANDLE);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_certify_is_listed,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_private_keys,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_secret_keys,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_always_authenticate,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_sizes_and_parts,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_refusals,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
