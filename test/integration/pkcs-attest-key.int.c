/* SPDX-License-Identifier: BSD-2-Clause */

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#include <tss2/tss2_mu.h>

#include "test.h"
#include "tpm2-pkcs11-vendor.h"

/*
 * CKM_TPM2_AK_PAIR_GEN and CKM_TPM2_CERTIFY_OBJECT (tpm2-pkcs11-vendor.h): an attestation key as
 * an object of the token, and TPM2_Certify signed by it, with no TPM handle in the client's hands.
 */

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

    rv = C_OpenSession(ti->slot_id, CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &ti->handle);
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

/* DER of the curve OIDs, as CKA_EC_PARAMS */
static CK_BYTE p256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
static CK_BYTE p384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
static CK_BYTE p192[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };

struct ak {
    CK_OBJECT_HANDLE pub;
    CK_OBJECT_HANDLE priv;
};

/* C_GenerateKeyPair of an attestation key; extra attributes go to the private template. */
static CK_RV ak_gen(CK_SESSION_HANDLE session, CK_BYTE *ec_params, CK_ULONG ec_params_len,
        CK_ATTRIBUTE *extra, CK_ULONG extra_len, struct ak *ak) {

    CK_BBOOL ck_true = CK_TRUE;
    CK_ATTRIBUTE pub[] = {
        { CKA_EC_PARAMS, ec_params, ec_params_len },
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
    };

    CK_ATTRIBUTE priv[8] = {
        { CKA_TOKEN, &ck_true, sizeof(ck_true) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
    };
    assert_true(extra_len <= ARRAY_LEN(priv) - 2);
    CK_ULONG priv_len = 2;
    for (CK_ULONG i = 0; i < extra_len; i++) {
        priv[priv_len++] = extra[i];
    }

    CK_MECHANISM mech = { CKM_TPM2_AK_PAIR_GEN, NULL, 0 };

    return C_GenerateKeyPair(session, &mech, pub, ARRAY_LEN(pub), priv, priv_len, &ak->pub, &ak->priv);
}

static void ak_gen_ok(CK_SESSION_HANDLE session, CK_BYTE *ec_params, CK_ULONG ec_params_len,
        struct ak *ak) {

    CK_RV rv = ak_gen(session, ec_params, ec_params_len, NULL, 0, ak);
    assert_int_equal(rv, CKR_OK);
}

/* The TPMT_PUBLIC in an object's CKA_TPM2_PUB_BLOB. */
static void read_public(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, TPM2B_PUBLIC *pub,
        CK_BYTE *blob, CK_ULONG *blob_len) {

    CK_ATTRIBUTE attr = { CKA_TPM2_PUB_BLOB, blob, *blob_len };
    CK_RV rv = C_GetAttributeValue(session, key, &attr, 1);
    assert_int_equal(rv, CKR_OK);
    *blob_len = attr.ulValueLen;

    size_t off = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(blob, *blob_len, &off, pub);
    assert_int_equal(rc, TSS2_RC_SUCCESS);
    assert_int_equal(off, *blob_len);
}

/* The mechanisms are listed: one generates key pairs, the other signs. */
static void test_ak_is_listed(void **state) {

    test_info *ti = test_info_from_state(state);

    CK_MECHANISM_TYPE mechs[256];
    CK_ULONG count = ARRAY_LEN(mechs);
    CK_RV rv = C_GetMechanismList(ti->slot_id, mechs, &count);
    assert_int_equal(rv, CKR_OK);

    bool gen = false, certify = false;
    for (CK_ULONG i = 0; i < count; i++) {
        gen |= mechs[i] == CKM_TPM2_AK_PAIR_GEN;
        certify |= mechs[i] == CKM_TPM2_CERTIFY_OBJECT;
    }
    assert_true(gen);
    assert_true(certify);

    CK_MECHANISM_INFO info;
    rv = C_GetMechanismInfo(ti->slot_id, CKM_TPM2_AK_PAIR_GEN, &info);
    assert_int_equal(rv, CKR_OK);
    assert_true(info.flags & CKF_GENERATE_KEY_PAIR);
    assert_true(info.flags & CKF_HW);

    rv = C_GetMechanismInfo(ti->slot_id, CKM_TPM2_CERTIFY_OBJECT, &info);
    assert_int_equal(rv, CKR_OK);
    assert_true(info.flags & CKF_SIGN);
    assert_true(info.flags & CKF_HW);
}

/*
 * The key pair is restricted, fixed to the TPM, signs with the curve's hash, and the token
 * refuses to sign data with it.
 */
static void test_ak_generate(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    struct {
        CK_BYTE *params;
        CK_ULONG params_len;
        TPM2_ECC_CURVE curve;
        TPMI_ALG_HASH hash;
    } curves[] = {
        { p256, sizeof(p256), TPM2_ECC_NIST_P256, TPM2_ALG_SHA256 },
        { p384, sizeof(p384), TPM2_ECC_NIST_P384, TPM2_ALG_SHA384 },
    };

    for (size_t i = 0; i < ARRAY_LEN(curves); i++) {
        struct ak ak;
        ak_gen_ok(session, curves[i].params, curves[i].params_len, &ak);

        CK_BBOOL sign = CK_TRUE, verify = CK_TRUE, extractable = CK_TRUE;
        CK_ULONG gen_mech = 0;
        CK_BYTE allowed[64];
        CK_ATTRIBUTE attrs[] = {
            { CKA_SIGN, &sign, sizeof(sign) },
            { CKA_EXTRACTABLE, &extractable, sizeof(extractable) },
            { CKA_KEY_GEN_MECHANISM, &gen_mech, sizeof(gen_mech) },
            { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
        };
        CK_RV rv = C_GetAttributeValue(session, ak.priv, attrs, ARRAY_LEN(attrs));
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(sign, CK_FALSE);
        assert_int_equal(extractable, CK_FALSE);
        assert_int_equal(gen_mech, CKM_TPM2_AK_PAIR_GEN);
        assert_int_equal(attrs[3].ulValueLen, 0);

        CK_ATTRIBUTE vattr = { CKA_VERIFY, &verify, sizeof(verify) };
        rv = C_GetAttributeValue(session, ak.pub, &vattr, 1);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(verify, CK_FALSE);

        CK_BYTE blob[1024];
        CK_ULONG blob_len = sizeof(blob);
        TPM2B_PUBLIC pub = { 0 };
        read_public(session, ak.priv, &pub, blob, &blob_len);
        const TPMT_PUBLIC *p = &pub.publicArea;
        assert_int_equal(p->type, TPM2_ALG_ECC);
        assert_int_equal(p->parameters.eccDetail.curveID, curves[i].curve);
        assert_int_equal(p->parameters.eccDetail.scheme.scheme, TPM2_ALG_ECDSA);
        assert_int_equal(p->parameters.eccDetail.scheme.details.ecdsa.hashAlg, curves[i].hash);
        const TPMA_OBJECT want = TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_SIGN_ENCRYPT
                | TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT | TPMA_OBJECT_SENSITIVEDATAORIGIN;
        assert_int_equal(p->objectAttributes & want, want);
        assert_int_equal(p->objectAttributes & TPMA_OBJECT_DECRYPT, 0);

        /* the module refuses to sign data with it, before the TPM would */
        CK_MECHANISM ecdsa = { CKM_ECDSA, NULL, 0 };
        rv = C_SignInit(session, &ecdsa, ak.priv);
        assert_int_equal(rv, CKR_MECHANISM_INVALID);
    }
}

/* What the templates may not ask for, and what the TPM cannot make. */
static void test_ak_template_refusals(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    struct ak ak;
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_FALSE;

    CK_ULONG usage[] = { CKA_SIGN, CKA_ENCRYPT, CKA_DECRYPT, CKA_VERIFY };
    for (size_t i = 0; i < ARRAY_LEN(usage); i++) {
        CK_ATTRIBUTE a = { usage[i], &ck_true, sizeof(ck_true) };
        CK_RV rv = ak_gen(session, p256, sizeof(p256), &a, 1, &ak);
        assert_int_equal(rv, CKR_TEMPLATE_INCONSISTENT);
    }

    /* the private key is sensitive: the module's own check of every key pair refuses it */
    CK_ATTRIBUTE extractable = { CKA_EXTRACTABLE, &ck_true, sizeof(ck_true) };
    CK_RV rv = ak_gen(session, p256, sizeof(p256), &extractable, 1, &ak);
    assert_int_equal(rv, CKR_ATTRIBUTE_VALUE_INVALID);

    /* saying what the key is anyway is fine */
    CK_ATTRIBUTE not_signing[] = {
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
    };
    rv = ak_gen(session, p256, sizeof(p256), not_signing, ARRAY_LEN(not_signing), &ak);
    assert_int_equal(rv, CKR_OK);

    /* a curve that is not P-256, P-384 or P-521 */
    rv = ak_gen(session, p192, sizeof(p192), NULL, 0, &ak);
    assert_int_not_equal(rv, CKR_OK);

    /* a mechanism parameter */
    CK_BBOOL param = CK_TRUE;
    CK_MECHANISM mech = { CKM_TPM2_AK_PAIR_GEN, &param, sizeof(param) };
    CK_ATTRIBUTE pub[] = { { CKA_EC_PARAMS, p256, sizeof(p256) } };
    CK_ATTRIBUTE priv[] = { { CKA_TOKEN, &ck_true, sizeof(ck_true) } };
    rv = C_GenerateKeyPair(session, &mech, pub, 1, priv, 1, &ak.pub, &ak.priv);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
}

/* The attestation key's public key, from its CKA_TPM2_PUB_BLOB. */
static EC_KEY *ak_eckey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE ak, int *nid, TPMI_ALG_HASH *hash) {

    CK_BYTE blob[1024];
    CK_ULONG blob_len = sizeof(blob);
    TPM2B_PUBLIC pub = { 0 };
    read_public(session, ak, &pub, blob, &blob_len);

    *hash = pub.publicArea.parameters.eccDetail.scheme.details.ecdsa.hashAlg;
    *nid = pub.publicArea.parameters.eccDetail.curveID == TPM2_ECC_NIST_P256 ?
            NID_X9_62_prime256v1 : NID_secp384r1;

    EC_KEY *key = EC_KEY_new_by_curve_name(*nid);
    assert_non_null(key);
    const TPMS_ECC_POINT *pt = &pub.publicArea.unique.ecc;
    BIGNUM *x = BN_bin2bn(pt->x.buffer, pt->x.size, NULL);
    BIGNUM *y = BN_bin2bn(pt->y.buffer, pt->y.size, NULL);
    assert_non_null(x);
    assert_non_null(y);
    assert_int_equal(EC_KEY_set_public_key_affine_coordinates(key, x, y), 1);
    BN_free(x);
    BN_free(y);

    return key;
}

static void hash_of(TPMI_ALG_HASH hash, const unsigned char *in, size_t len,
        unsigned char *out, unsigned int *out_len) {

    const EVP_MD *md = hash == TPM2_ALG_SHA256 ? EVP_sha256() : EVP_sha384();
    assert_int_equal(EVP_Digest(in, len, out, out_len, md, NULL), 1);
}

/*
 * Everything a client checks of a statement: it parses to the end, is a certify statement of this
 * nonce, names the object by the Name of its CKA_TPM2_PUB_BLOB, and is signed by the attestation
 * key whose public key the client read from the token.
 */
static void check_statement(CK_SESSION_HANDLE session, struct ak *ak, CK_OBJECT_HANDLE key,
        const CK_BYTE *data, CK_ULONG data_len, const CK_BYTE *out, CK_ULONG out_len) {

    CK_BYTE blob[1024];
    CK_ULONG blob_len = sizeof(blob);
    TPM2B_PUBLIC pub = { 0 };
    read_public(session, key, &pub, blob, &blob_len);

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

    const TPM2B_NAME *name = &attest.attested.certify.name;
    assert_int_equal(name->size, 2 + SHA256_DIGEST_LENGTH);
    assert_int_equal((name->name[0] << 8) | name->name[1], TPM2_ALG_SHA256);
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(&blob[2], blob_len - 2, digest);
    assert_memory_equal(&name->name[2], digest, sizeof(digest));

    int nid;
    TPMI_ALG_HASH hash;
    EC_KEY *eckey = ak_eckey(session, ak->priv, &nid, &hash);

    assert_int_equal(signature.sigAlg, TPM2_ALG_ECDSA);
    assert_int_equal(signature.signature.ecdsa.hash, hash);
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int md_len = 0;
    hash_of(hash, attest2b.attestationData, attest2b.size, md, &md_len);

    ECDSA_SIG *sig = ECDSA_SIG_new();
    assert_non_null(sig);
    BIGNUM *r = BN_bin2bn(signature.signature.ecdsa.signatureR.buffer, signature.signature.ecdsa.signatureR.size, NULL);
    BIGNUM *s = BN_bin2bn(signature.signature.ecdsa.signatureS.buffer, signature.signature.ecdsa.signatureS.size, NULL);
    assert_non_null(r);
    assert_non_null(s);
    assert_int_equal(ECDSA_SIG_set0(sig, r, s), 1);
    assert_int_equal(ECDSA_do_verify(md, md_len, sig, eckey), 1);
    ECDSA_SIG_free(sig);
    EC_KEY_free(eckey);
}

static CK_RV certify_init(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_OBJECT_HANDLE signer) {

    CK_TPM2_CERTIFY_OBJECT_PARAMS params = { .hSigner = signer };
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY_OBJECT, &params, sizeof(params) };

    return C_SignInit(session, &mech, key);
}

static CK_RV certify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key, CK_OBJECT_HANDLE signer,
        const CK_BYTE *data, CK_ULONG data_len, CK_BYTE *out, CK_ULONG *out_len) {

    CK_RV rv = certify_init(session, key, signer);
    if (rv != CKR_OK) {
        return rv;
    }

    return C_Sign(session, (CK_BYTE_PTR)data, data_len, out, out_len);
}

/*
 * Keys of the token are certified by an attestation key of the token: private keys of each type,
 * secret keys, with each curve's attestation key, and the statements verify.
 */
static void test_certify_object(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    /* the keys to certify, found before the attestation keys exist */
    CK_OBJECT_HANDLE keys[3];
    CK_OBJECT_HANDLE pub;
    get_keypair(session, CKK_EC, &pub, &keys[0]);
    get_keypair(session, CKK_RSA, &pub, &keys[1]);

    CK_OBJECT_CLASS secret = CKO_SECRET_KEY;
    CK_BBOOL always_authenticate = CK_FALSE;
    CK_ATTRIBUTE tmpl[] = {
        { CKA_CLASS, &secret, sizeof(secret) },
        { CKA_ALWAYS_AUTHENTICATE, &always_authenticate, sizeof(always_authenticate) },
    };
    CK_RV rv = C_FindObjectsInit(session, tmpl, ARRAY_LEN(tmpl));
    assert_int_equal(rv, CKR_OK);
    CK_ULONG count = 0;
    rv = C_FindObjects(session, &keys[2], 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);
    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE *curves[] = { p256, p384 };
    CK_ULONG curves_len[] = { sizeof(p256), sizeof(p384) };
    for (size_t c = 0; c < ARRAY_LEN(curves); c++) {
        struct ak ak;
        ak_gen_ok(session, curves[c], curves_len[c], &ak);

        for (size_t i = 0; i < ARRAY_LEN(keys); i++) {
            CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
            CK_ULONG out_len = sizeof(out);
            rv = certify(session, keys[i], ak.priv, nonce, sizeof(nonce), out, &out_len);
            assert_int_equal(rv, CKR_OK);
            check_statement(session, &ak, keys[i], nonce, sizeof(nonce), out, out_len);
        }

        /* the mechanism's output bound, and the part form, are CKM_TPM2_CERTIFY's */
        CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
        CK_ULONG out_len = 0;
        rv = certify_init(session, keys[0], ak.priv);
        assert_int_equal(rv, CKR_OK);
        rv = C_Sign(session, (CK_BYTE_PTR)nonce, sizeof(nonce), NULL, &out_len);
        assert_int_equal(rv, CKR_OK);
        assert_int_equal(out_len, CK_TPM2_CERTIFY_MAX_LEN);
        rv = C_SignUpdate(session, (CK_BYTE_PTR)nonce, 7);
        assert_int_equal(rv, CKR_OK);
        out_len = sizeof(out);
        rv = C_SignFinal(session, out, &out_len);
        assert_int_equal(rv, CKR_OK);
        check_statement(session, &ak, keys[0], nonce, 7, out, out_len);
    }
}

/*
 * The signer must be an attestation key of the token; each refusal leaves the session fit to
 * certify, and the signer in use by no operation.
 */
static void test_certify_object_refusals(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_OBJECT_HANDLE pub, priv;
    get_keypair(session, CKK_EC, &pub, &priv);

    struct ak ak;
    ak_gen_ok(session, p256, sizeof(p256), &ak);

    CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
    CK_ULONG out_len = sizeof(out);

    /* an ordinary key of the token does not sign statements */
    CK_RV rv = certify(session, ak.priv, priv, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    /* nor a public key object */
    rv = certify(session, priv, ak.pub, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    /* nor something that is no object */
    rv = certify(session, priv, 0x7fff0000UL, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    /* an attestation key does not certify itself */
    rv = certify(session, ak.priv, ak.priv, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* the parameter: missing, of another length */
    CK_TPM2_CERTIFY_OBJECT_PARAMS params = { .hSigner = ak.priv };
    CK_MECHANISM mech = { CKM_TPM2_CERTIFY_OBJECT, NULL, 0 };
    rv = C_SignInit(session, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);
    mech.pParameter = &params;
    mech.ulParameterLen = sizeof(params) - 1;
    rv = C_SignInit(session, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_PARAM_INVALID);

    /* it signs; there is nothing to verify */
    mech.ulParameterLen = sizeof(params);
    rv = C_VerifyInit(session, &mech, priv);
    assert_int_equal(rv, CKR_MECHANISM_INVALID);

    /* too long a nonce */
    CK_BYTE too_long[CK_TPM2_CERTIFY_MAX_QUALIFYING_LEN + 1] = { 0 };
    out_len = sizeof(out);
    rv = certify(session, priv, ak.priv, too_long, sizeof(too_long), out, &out_len);
    assert_int_equal(rv, CKR_DATA_LEN_RANGE);

    /* none of it left an operation active or the attestation key in use */
    out_len = sizeof(out);
    rv = certify(session, priv, ak.priv, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_statement(session, &ak, priv, nonce, sizeof(nonce), out, out_len);

    /* the user must be logged in */
    logout(session);
    rv = certify_init(session, priv, ak.priv);
    assert_int_equal(rv, CKR_USER_NOT_LOGGED_IN);
}

/* The attestation key is an object of the token like any other: it is still there after a restart. */
static void test_ak_persists(void **state) {

    test_info *ti = test_info_from_state(state);
    CK_SESSION_HANDLE session = ti->handle;

    user_login(session);

    CK_OBJECT_HANDLE pub, priv;
    get_keypair(session, CKK_EC, &pub, &priv);

    CK_BYTE label[] = "attestation-key";
    CK_ATTRIBUTE label_attr = { CKA_LABEL, label, sizeof(label) - 1 };
    struct ak ak;
    CK_RV rv = ak_gen(session, p256, sizeof(p256), &label_attr, 1, &ak);
    assert_int_equal(rv, CKR_OK);

    CK_BYTE blob_before[1024];
    CK_ULONG blob_before_len = sizeof(blob_before);
    TPM2B_PUBLIC pub_before = { 0 };
    read_public(session, ak.priv, &pub_before, blob_before, &blob_before_len);

    /* the token is closed and opened again, as a new process would find it */
    rv = C_Finalize(NULL);
    assert_int_equal(rv, CKR_OK);
    rv = C_Initialize(NULL);
    assert_int_equal(rv, CKR_OK);

    CK_SLOT_ID slots[6];
    CK_ULONG count = ARRAY_LEN(slots);
    rv = C_GetSlotList(true, slots, &count);
    assert_int_equal(rv, CKR_OK);
    rv = C_OpenSession(slots[0], CKF_SERIAL_SESSION | CKF_RW_SESSION, NULL, NULL, &session);
    assert_int_equal(rv, CKR_OK);
    user_login(session);
    ti->handle = session;

    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_ATTRIBUTE find[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_LABEL, label, sizeof(label) - 1 },
    };
    rv = C_FindObjectsInit(session, find, ARRAY_LEN(find));
    assert_int_equal(rv, CKR_OK);
    rv = C_FindObjects(session, &ak.priv, 1, &count);
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(count, 1);
    rv = C_FindObjectsFinal(session);
    assert_int_equal(rv, CKR_OK);

    /* still the same key, still not a key to sign data with, and still certifying */
    CK_BYTE blob_after[1024];
    CK_ULONG blob_after_len = sizeof(blob_after);
    TPM2B_PUBLIC pub_after = { 0 };
    read_public(session, ak.priv, &pub_after, blob_after, &blob_after_len);
    assert_int_equal(blob_after_len, blob_before_len);
    assert_memory_equal(blob_after, blob_before, blob_before_len);

    CK_BYTE allowed[64];
    CK_BBOOL sign = CK_TRUE;
    CK_ATTRIBUTE attrs[] = {
        { CKA_SIGN, &sign, sizeof(sign) },
        { CKA_ALLOWED_MECHANISMS, allowed, sizeof(allowed) },
    };
    rv = C_GetAttributeValue(session, ak.priv, attrs, ARRAY_LEN(attrs));
    assert_int_equal(rv, CKR_OK);
    assert_int_equal(sign, CK_FALSE);
    assert_int_equal(attrs[1].ulValueLen, 0);

    get_keypair(session, CKK_EC, &pub, &priv);
    CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
    CK_ULONG out_len = sizeof(out);
    rv = certify(session, priv, ak.priv, nonce, sizeof(nonce), out, &out_len);
    assert_int_equal(rv, CKR_OK);
    check_statement(session, &ak, priv, nonce, sizeof(nonce), out, out_len);
}

int main() {

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ak_is_listed,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ak_generate,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ak_template_refusals,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_object,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_certify_object_refusals,
            test_setup, test_teardown),
        cmocka_unit_test_setup_teardown(test_ak_persists,
            test_setup, test_teardown),
    };

    return cmocka_run_group_tests(tests, group_setup, group_teardown);
}
