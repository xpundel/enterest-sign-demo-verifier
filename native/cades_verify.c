#define UNIX
#define CADES_PARA_HAS_EXTRA_FIELDS

#include <stdarg.h>
#include <cades.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void trace_stage(const char *stage) {
    fprintf(stderr, "stage=%s\n", stage);
    fflush(stderr);
}

static int read_file(const char *path, BYTE **data, DWORD *size) {
    FILE *file = fopen(path, "rb");
    long length;
    BYTE *buffer;

    if (file == NULL || fseek(file, 0, SEEK_END) != 0 || (length = ftell(file)) < 0 ||
        (uint64_t)length > UINT32_MAX || fseek(file, 0, SEEK_SET) != 0) {
        if (file != NULL) fclose(file);
        return 0;
    }
    buffer = malloc(length > 0 ? (size_t)length : 1);
    if (buffer == NULL || (length > 0 && fread(buffer, 1, (size_t)length, file) != (size_t)length)) {
        free(buffer);
        fclose(file);
        return 0;
    }
    fclose(file);
    *data = buffer;
    *size = (DWORD)length;
    return 1;
}

static int signer_count(const BYTE *signature, DWORD signature_size, DWORD *count) {
    HCRYPTMSG message = CryptMsgOpenToDecode(
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING,
        CMSG_DETACHED_FLAG,
        0,
        0,
        NULL,
        NULL
    );
    DWORD count_size = sizeof(*count);
    int ok = message != 0 &&
        CryptMsgUpdate(message, signature, signature_size, TRUE) &&
        CryptMsgGetParam(message, CMSG_SIGNER_COUNT_PARAM, 0, count, &count_size);
    if (message != 0) CryptMsgClose(message);
    return ok;
}

static const char *status_name(DWORD status) {
    switch (status) {
        case CADES_VERIFY_SUCCESS: return "CADES_VERIFY_SUCCESS";
        case CADES_VERIFY_INVALID_REFS_AND_VALUES: return "CADES_VERIFY_INVALID_REFS_AND_VALUES";
        case CADES_VERIFY_SIGNER_NOT_FOUND: return "CADES_VERIFY_SIGNER_NOT_FOUND";
        case CADES_VERIFY_REFS_AND_VALUES_NO_MATCH: return "CADES_VERIFY_REFS_AND_VALUES_NO_MATCH";
        case CADES_VERIFY_NO_CHAIN: return "CADES_VERIFY_NO_CHAIN";
        case CADES_VERIFY_END_CERT_REVOCATION: return "CADES_VERIFY_END_CERT_REVOCATION";
        case CADES_VERIFY_CHAIN_CERT_REVOCATION: return "CADES_VERIFY_CHAIN_CERT_REVOCATION";
        case CADES_VERIFY_BAD_SIGNATURE: return "CADES_VERIFY_BAD_SIGNATURE";
        case CADES_VERIFY_ECONTENTTYPE_NO_MATCH: return "CADES_VERIFY_ECONTENTTYPE_NO_MATCH";
        default: return "CADES_VERIFY_FAILED";
    }
}

static long long filetime_to_unix(const FILETIME *value) {
    uint64_t ticks;
    if (value == NULL) return 0;
    ticks = ((uint64_t)value->dwHighDateTime << 32) | value->dwLowDateTime;
    if (ticks < 116444736000000000ULL) return 0;
    return (long long)(ticks / 10000000ULL - 11644473600ULL);
}

static void print_hex(const BYTE *data, DWORD size) {
    DWORD index;
    if (data == NULL || size == 0) {
        putchar('-');
        return;
    }
    for (index = 0; index < size; index++) printf("%02x", data[index]);
}

int main(int argc, char **argv) {
    BYTE *document = NULL;
    BYTE *signature = NULL;
    DWORD document_size = 0;
    DWORD signature_size = 0;
    DWORD count = 0;
    DWORD index;
    int exit_code = 0;

    if (argc != 3 || !read_file(argv[1], &document, &document_size) ||
        !read_file(argv[2], &signature, &signature_size)) {
        puts("E\tINPUT_READ_FAILED\t0x00000000");
        exit_code = 2;
        goto cleanup;
    }
    trace_stage("input_read");
    if (!signer_count(signature, signature_size, &count) || count == 0 || count > 32) {
        printf("E\tCMS_PARSE_FAILED\t0x%08x\n", (unsigned int)GetLastError());
        goto cleanup;
    }
    fprintf(stderr, "stage=cms_parsed signer_count=%u\n", (unsigned int)count);
    fflush(stderr);

    printf("V\t1\t%u\n", (unsigned int)count);
    for (index = 0; index < count; index++) {
        CRYPT_VERIFY_MESSAGE_PARA crypt = {sizeof(crypt)};
        CADES_VERIFICATION_PARA cades = {sizeof(cades)};
        CADES_VERIFY_MESSAGE_PARA parameters = {sizeof(parameters)};
        PCADES_VERIFICATION_INFO info = NULL;
        const BYTE *parts[] = {document};
        DWORD part_sizes[] = {document_size};
        BOOL api_ok;
        DWORD error_code;
        DWORD status;

        crypt.dwMsgAndCertEncodingType = X509_ASN_ENCODING | PKCS_7_ASN_ENCODING;
        cades.dwCadesType = CADES_BES;
#ifdef CADES_SKIP_IE_PROXY_CONFIGURATION
        cades.dwFlags = CADES_SKIP_IE_PROXY_CONFIGURATION;
#endif
        parameters.pVerifyMessagePara = &crypt;
        parameters.pCadesVerifyPara = &cades;

        fprintf(stderr, "stage=verify_started signer_index=%u\n", (unsigned int)index);
        fflush(stderr);
        SetLastError(0);
        api_ok = CadesVerifyDetachedMessage(
            &parameters,
            index,
            signature,
            signature_size,
            1,
            parts,
            part_sizes,
            &info
        );
        error_code = GetLastError();
        status = info != NULL ? info->dwStatus : 0xffffffffU;
		if (api_ok && status == CADES_VERIFY_SUCCESS) error_code = 0;
        fprintf(
            stderr,
            "stage=verify_finished signer_index=%u api_ok=%d status=%s error=0x%08x\n",
            (unsigned int)index,
            api_ok ? 1 : 0,
            status_name(status),
            (unsigned int)error_code
        );
        fflush(stderr);

        printf(
            "S\t%u\t%d\t%s\t0x%08x\t%lld\t%lld\t",
            (unsigned int)index,
            api_ok ? 1 : 0,
            status_name(status),
            (unsigned int)error_code,
            filetime_to_unix(info != NULL ? info->pSigningTime : NULL),
            filetime_to_unix(info != NULL ? info->pSignatureTimeStampTime : NULL)
        );
        if (info != NULL && info->pSignerCert != NULL) {
            print_hex(info->pSignerCert->pbCertEncoded, info->pSignerCert->cbCertEncoded);
        } else {
            print_hex(NULL, 0);
        }
        putchar('\n');
        if (info != NULL) CadesFreeVerificationInfo(info);
    }

cleanup:
    free(document);
    free(signature);
    return exit_code;
}
