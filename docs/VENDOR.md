# Vendor-defined interface

tpm2-pkcs11 defines a few PKCS#11 attributes and mechanisms of its own, in the vendor ranges
of the specification. The ones listed in [`src/tpm2-pkcs11-vendor.h`](/src/tpm2-pkcs11-vendor.h)
are a stable interface, and that header is installed (`$(includedir)/tpm2-pkcs11/`); include it
after the Cryptoki header. Other vendor attributes (`CKA_TPM2_OBJAUTH_ENC`, `CKA_TPM2_PRIV_BLOB`,
`CKA_TPM2_ENC_BLOB`, `CKA_TPM2_SERIALIZED_TR`) are the module's own bookkeeping, may be returned by
`C_GetAttributeValue`, and are not stable: do not use them.

The vendor range is `0x0F000000` within `CKA_VENDOR_DEFINED` (attributes) and
`CKM_VENDOR_DEFINED` (mechanisms).

## `CKA_TPM2_PUB_BLOB`

The key object's TPM public area, marshaled as a `TPM2B_PUBLIC`: a big-endian 16-bit size, then the
`TPMT_PUBLIC`. Every key object that lives in the TPM has one (public, private and secret keys), and
it can be read in any session that can see the object.

The object's TPM Name is the 16-bit name algorithm followed by that algorithm's digest of the
`TPMT_PUBLIC` (the bytes after the size). A client computes it and compares it with what the TPM
attested, as below.

## `CKM_TPM2_CERTIFY`

`TPM2_Certify` for a key object, signed by a key of the TPM that the caller names. It answers
"is this PKCS#11 object a key that sits in this TPM, loaded with the private area the module holds
for it?" with a statement signed by the TPM itself, which the client verifies without trusting
the module.

It is used with `C_SignInit` and `C_Sign` (or `C_SignUpdate` and `C_SignFinal`):

| | |
|---|---|
| key | the key object to certify: a private or secret key in the TPM. A public key object is refused (`CKR_KEY_TYPE_INCONSISTENT`) |
| parameter | `CK_TPM2_CERTIFY_PARAMS`: `ulSignerHandle`, the persistent handle (`0x81000000` to `0x81FFFFFF`) of the signing key |
| data | the qualifying data, a nonce of 0 to 64 bytes the TPM signs into the statement (`CKR_DATA_LEN_RANGE` above that) |
| output | the marshaled `TPM2B_ATTEST` followed by the marshaled `TPMT_SIGNATURE`. The buffer must hold `CK_TPM2_CERTIFY_MAX_LEN` bytes; a call with a `NULL` output returns that length without using the TPM |

The user must be logged in, and a key with `CKA_ALWAYS_AUTHENTICATE` needs the context login, as for
any use of it. `CKA_SIGN` and `CKA_ALLOWED_MECHANISMS` of the key object are not consulted: the
mechanism signs nothing the key holder chose, and it certifies keys that can sign nothing (a
decrypt-only RSA key, an AES or HMAC key). The mechanism is listed by `C_GetMechanismList` and has
`CKF_SIGN`, so a client can detect it.

The signer is a key the caller made: an empty auth value and a signing key, in practice a restricted
signing key (an attestation key), which signs only TPM-generated structures. tpm2-pkcs11 only uses
it, never creates or changes it. An unknown handle, a key the TPM refuses to sign with, and a key
whose auth value is not empty are `CKR_MECHANISM_PARAM_INVALID`. A key with an auth value that is not
marked `noDA` counts that refusal as a failed authorization against the TPM's dictionary-attack
lockout, so make the signer with an empty auth value. The signature is made with the signer's own
scheme.

```sh
# An attestation key at a persistent handle, and its public key for verifying with
tpm2_createprimary -C o -c primary.ctx
tpm2_create -C primary.ctx -G ecc256:ecdsa-sha256:null -c ak.ctx \
    -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|restricted|sign'
tpm2_evictcontrol -C o -c ak.ctx 0x81000016
tpm2_readpublic -c 0x81000016 -f pem -o ak.pem
```

### What the client verifies

The module is not trusted for the statement: a module that lies cannot produce a TPM signature. A
client checks:

1. The output parses completely: a `TPM2B_ATTEST` (its `attestationData` is a `TPMS_ATTEST`) and a
   `TPMT_SIGNATURE`, with nothing left over.
2. The signature is the signer's, over the exact bytes of `attestationData`, under the signer's
   public key that the client holds.
3. `magic` is `TPM_GENERATED_VALUE`, `type` is `TPM_ST_ATTEST_CERTIFY`, and `extraData` is the nonce
   the client sent (a fresh nonce makes the statement a proof of now, not a replay).
4. The attested Name is the Name of the object's `CKA_TPM2_PUB_BLOB`, and the qualified signer is
   the signer's qualified Name.
5. The attested `objectAttributes` are what the client relies on (`fixedTPM`, `fixedParent`,
   `sensitiveDataOrigin`): the signed bits say whether the key was generated in the TPM and whether it
   can leave it.

`test/integration/pkcs-certify.int.c` does 1 to 4 with OpenSSL and the TSS marshaling library.

```c
CK_TPM2_CERTIFY_PARAMS params = { .ulSignerHandle = 0x81000016 };
CK_MECHANISM mech = { CKM_TPM2_CERTIFY, &params, sizeof(params) };
CK_BYTE out[CK_TPM2_CERTIFY_MAX_LEN];
CK_ULONG out_len = sizeof(out);

rv = C_SignInit(session, &mech, key);
rv = C_Sign(session, nonce, nonce_len, out, &out_len);
```

## `CKM_TPM2_AK_PAIR_GEN`

`C_GenerateKeyPair` of an attestation key as an ordinary key pair of the token, so that a client
needs no TPM handle and no access to the TPM to have one. The mechanism takes no parameter; the
templates are the EC key pair's (`CKA_EC_PARAMS`, `CKA_TOKEN`, `CKA_PRIVATE`, a label, an id...).

The TPM key is fixed:

- restricted, so it signs only digests of TPM-generated structures such as a certify statement,
  never data a caller chose; a signing key, with the ECDSA scheme over the curve's hash (P-256 and
  SHA-256, P-384 and SHA-384, P-521 and SHA-512, `CKR_CURVE_NOT_SUPPORTED` for any other curve);
- `fixedTPM`, `fixedParent`, `sensitiveDataOrigin`, `userWithAuth`: it never leaves the TPM, and
  its auth value is the module's own, like any key of the token.

The private key has `CKA_SIGN` false, and a `CKA_ALLOWED_MECHANISMS` with no mechanism in it, so
`C_SignInit` refuses it in the module instead of failing in the TPM, which asks a restricted key
for a hashcheck ticket. `CKA_KEY_GEN_MECHANISM` is `CKM_TPM2_AK_PAIR_GEN`. A template that asks for
`CKA_SIGN`, `CKA_VERIFY`, `CKA_ENCRYPT` or `CKA_DECRYPT` true is `CKR_TEMPLATE_INCONSISTENT`, as is
one that makes the key extractable. That the key is restricted is in the `TPMA_OBJECT` of its
`CKA_TPM2_PUB_BLOB`, and a client that trusts the key only if it is checks it there.

## `CKM_TPM2_CERTIFY_OBJECT`

`CKM_TPM2_CERTIFY`, with the signer a private key made by `CKM_TPM2_AK_PAIR_GEN` and named by its
object handle: parameter `CK_TPM2_CERTIFY_OBJECT_PARAMS`, `hSigner`. The key, the qualifying data,
the output and the checks are those of `CKM_TPM2_CERTIFY`. Any other signer (an ordinary key of the
token, a public key object, no object at all, the key itself) is `CKR_MECHANISM_PARAM_INVALID`:
only an attestation key signs statements about the TPM.

What differs for the client is the signer. It identifies the attestation key by the public key it
read from the token (`CKA_TPM2_PUB_BLOB`, or `CKA_EC_POINT`) and pinned, and verifies the signature
under it. The attested qualified signer is the qualified Name of a key under the token's primary
key, which a client without TPM access cannot compute, so check 4's last half above does not apply:
the key that signed is the pinned public key, and that it is fixed to this TPM is what the
`TPMA_OBJECT` of its `CKA_TPM2_PUB_BLOB` says.

```c
CK_MECHANISM gen = { CKM_TPM2_AK_PAIR_GEN, NULL, 0 };
rv = C_GenerateKeyPair(session, &gen, pub_template, pub_count, priv_template, priv_count, &ak_pub, &ak_priv);

CK_TPM2_CERTIFY_OBJECT_PARAMS params = { .hSigner = ak_priv };
CK_MECHANISM mech = { CKM_TPM2_CERTIFY_OBJECT, &params, sizeof(params) };
rv = C_SignInit(session, &mech, key);
rv = C_Sign(session, nonce, nonce_len, out, &out_len);
```

`test/integration/pkcs-attest-key.int.c` generates attestation keys on two curves, certifies private
and secret keys and verifies the statements with OpenSSL, and checks the refusals and that the key
survives a restart of the token.
