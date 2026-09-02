/*
 * Reproducer: OpenSSL does not reject prohibited keyUsage values for ML-DSA
 * certificates per RFC 9881 Section 5.
 *
 * https://www.rfc-editor.org/rfc/rfc9881.html#section-5
 */

#include <stdio.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/opensslv.h>

static int add_ext(X509 *cert, int nid, const char *value)
{
    X509V3_CTX ctx;
    X509_EXTENSION *ext;

    X509V3_set_ctx_nodb(&ctx);
    X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);

    ext = X509V3_EXT_nconf_nid(NULL, &ctx, nid, value);
    if (!ext)
        return 0;

    X509_add_ext(cert, ext, -1);
    X509_EXTENSION_free(ext);
    return 1;
}

int main(void)
{
    EVP_PKEY_CTX *pctx = NULL;
    EVP_PKEY *pkey = NULL;
    X509 *cert = NULL;
    X509_NAME *name = NULL;
    ASN1_INTEGER *serial = NULL;
    BIO *bio = NULL;
    int ret = 1;
    int i, ext_count;

    /* Generate ML-DSA-65 key pair. */
    pctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-DSA-65", NULL);
    if (!pctx) {
        fprintf(stderr, "EVP_PKEY_CTX_new_from_name failed\n");
        goto err;
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0) {
        fprintf(stderr, "EVP_PKEY_keygen_init failed\n");
        goto err;
    }
    if (EVP_PKEY_generate(pctx, &pkey) <= 0) {
        fprintf(stderr, "EVP_PKEY_generate failed\n");
        goto err;
    }

    /* Create X509 certificate. */
    cert = X509_new();
    if (!cert) {
        fprintf(stderr, "X509_new failed\n");
        goto err;
    }

    /* Version 3 (value 2). */
    X509_set_version(cert, 2);

    /* Serial number 1. */
    serial = ASN1_INTEGER_new();
    ASN1_INTEGER_set(serial, 1);
    X509_set_serialNumber(cert, serial);
    ASN1_INTEGER_free(serial);
    serial = NULL;

    /* Validity: now to now + 1 day. */
    X509_gmtime_adj(X509_getm_notBefore(cert), 0);
    X509_gmtime_adj(X509_getm_notAfter(cert), 86400);

    /* Set public key. */
    X509_set_pubkey(cert, pkey);

    /* Subject and issuer: CN=test, DC=example (self-signed). */
    name = X509_NAME_new();
    if (!name) {
        fprintf(stderr, "X509_NAME_new failed\n");
        goto err;
    }
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               (const unsigned char *)"test", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "DC", MBSTRING_ASC,
                               (const unsigned char *)"example", -1, -1, 0);
    X509_set_subject_name(cert, name);
    X509_set_issuer_name(cert, name);

    /* Add extensions. */
    if (!add_ext(cert, NID_basic_constraints, "CA:FALSE")) {
        fprintf(stderr, "Failed to add basicConstraints\n");
        goto err;
    }

    /*
     * All five prohibited keyUsage values for ML-DSA per RFC 9881 Section 5,
     * combined with digitalSignature (the only valid one).
     */
    if (!add_ext(cert, NID_key_usage,
                 "digitalSignature,keyEncipherment,dataEncipherment,"
                 "keyAgreement,encipherOnly,decipherOnly")) {
        fprintf(stderr, "Failed to add keyUsage\n");
        goto err;
    }

    if (!add_ext(cert, NID_subject_key_identifier, "hash")) {
        fprintf(stderr, "Failed to add subjectKeyIdentifier\n");
        goto err;
    }

    /* Sign the certificate (ML-DSA does not use a separate digest). */
    if (X509_sign(cert, pkey, NULL) <= 0) {
        fprintf(stderr, "X509_sign failed\n");
        ERR_print_errors_fp(stderr);
        goto err;
    }

    /* Print results. */
    printf("OpenSSL version: %s\n", OpenSSL_version(OPENSSL_VERSION));
    printf("\n");

    /* Find and print keyUsage extension value. */
    ext_count = X509_get_ext_count(cert);
    for (i = 0; i < ext_count; i++) {
        const X509_EXTENSION *e = X509_get_ext(cert, i);

        if (OBJ_obj2nid(X509_EXTENSION_get_object(e)) == NID_key_usage) {
            bio = BIO_new(BIO_s_mem());
            if (bio && X509V3_EXT_print(bio, e, 0, 0)) {
                char *buf = NULL;
                long len = BIO_get_mem_data(bio, &buf);
                printf("keyUsage: %.*s\n", (int)len, buf);
            }
            BIO_free(bio);
            bio = NULL;
            break;
        }
    }

    printf("\n");
    printf("Certificate was signed successfully with prohibited keyUsage values.\n");
    printf("OpenSSL should have rejected this per RFC 9881 Section 5.\n");
    ret = 0;

err:
    if (ret != 0)
        ERR_print_errors_fp(stderr);
    X509_NAME_free(name);
    EVP_PKEY_free(pkey);
    EVP_PKEY_CTX_free(pctx);
    X509_free(cert);
    return ret;
}
