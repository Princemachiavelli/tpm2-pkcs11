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

## `CKA_TPM2_EK_PUB_BLOB` and `CKM_TPM2_ACTIVATE_CREDENTIAL`

Chaining an attestation key to the TPM's Endorsement Key certificate answers "is this a genuine
TPM?", not only "is it the same TPM as at first use". The client makes a credential, with
`TPM2_MakeCredential`, for the EK's public key and the attestation key's Name: only a TPM that holds
both, the EK for which the manufacturer issued the certificate and that attestation key, can
recover it.

`CKA_TPM2_EK_PUB_BLOB` is on the private key of an attestation key: the public area of the default
RSA 2048 EK of the TCG EK Credential Profile, a `TPM2B_PUBLIC`. It is a function of the TPM's
endorsement seed and the template only, so it is the key of the manufacturer's EK certificate (the
test compares it byte for byte with what `tpm2_createek` makes). It is absent if the endorsement
hierarchy had an auth value when the key was made. The EK is not an object of the token: it is a
primary of the endorsement hierarchy, not a child of the token's primary, and the module makes it
for the operation and flushes it.

`CKA_TPM2_EK_CERT` is next to it: the X.509 certificate (DER) in the TPM's NV index `0x01C00002`,
where the TCG EK Credential Profile puts the RSA EK certificate, as it was when the attestation key
was made; absent if there was none or the owner's or index's empty auth did not read it. A client
then needs no access to the TPM for it either.

Both identify the TPM for good, so only the user reads them: a `C_GetAttributeValue` without the
user login is `CKR_ATTRIBUTE_SENSITIVE`, whatever handle the caller holds, and an attestation key
must be a private object (`CKA_PRIVATE` false is `CKR_TEMPLATE_INCONSISTENT`).

`CKM_TPM2_ACTIVATE_CREDENTIAL` is `TPM2_ActivateCredential` with the attestation key and that EK,
used with `C_DecryptInit` and `C_Decrypt`:

| | |
|---|---|
| key | the private key of an attestation key (`CKR_KEY_TYPE_INCONSISTENT` for any other, and for a public key object). `CKA_ALLOWED_MECHANISMS` is not consulted |
| parameter | none |
| input | the `TPM2B_ID_OBJECT` followed by the `TPM2B_ENCRYPTED_SECRET` of `TPM2_MakeCredential`, marshaled and concatenated (the file `tpm2_makecredential` writes has an 8 byte header before them: leave it out). Not parsing to the end, damaged, or made for another key or Name is `CKR_ENCRYPTED_DATA_INVALID`; over `CK_TPM2_ACTIVATE_CREDENTIAL_MAX_INPUT_LEN` bytes, `CKR_ENCRYPTED_DATA_LEN_RANGE` |
| output | the credential, at most 32 bytes (the digest size of the EK's name algorithm). The buffer must hold `CK_TPM2_ACTIVATE_CREDENTIAL_MAX_LEN` bytes; a call with a `NULL` output returns that length without using the TPM |

The module authorizes the EK with `PolicySecret(TPM_RH_ENDORSEMENT)` and an empty endorsement auth
value, which is how a TPM that has not been taken is: with another value the operation is
`CKR_GENERAL_ERROR`. The user must be logged in. As with any decryption, a buffer too small keeps the
operation, and any other error ends it.

### What the client verifies

The module is not trusted for the EK: a module that lies could hand out a software RSA key as
`CKA_TPM2_EK_PUB_BLOB`, decrypt the credential itself and "activate" with no TPM involved. What
stops that is the certificate, which only a manufacturer's TPM has. A client checks:

1. The EK certificate (`CKA_TPM2_EK_CERT`, or the manufacturer's service) chains to the
   manufacturer's CA that the client trusts, and its public key is the modulus of
   `CKA_TPM2_EK_PUB_BLOB`.
2. The attestation key is what the client relies on: its `CKA_TPM2_PUB_BLOB` shows `restricted`,
   `fixedTPM`, `fixedParent` (as for `CKM_TPM2_CERTIFY_OBJECT`).
3. The credential was made for that EK and the Name computed from that `CKA_TPM2_PUB_BLOB`, with a
   fresh random credential, and what the module returns is that credential.

```sh
# the client: nothing of the TPM needed. ek.pub is CKA_TPM2_EK_PUB_BLOB, the Name is
# 000b followed by the SHA-256 of the TPMT_PUBLIC in CKA_TPM2_PUB_BLOB (after its 2 byte size).
tpm2_makecredential -T none -e ek.pub -s credential.bin -n "$ak_name" -o cred.out
tail -c +9 cred.out > input.bin     # the CKM_TPM2_ACTIVATE_CREDENTIAL input
```

`test/integration/pkcs-activate-credential.int.c` makes credentials with `TPM2_MakeCredential` and
recovers them, and checks the EK against `tpm2_createek`, the refusals and the sizes.
