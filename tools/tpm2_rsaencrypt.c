/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdlib.h>
#include <sys/time.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "object.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_rsaencrypt_ctx tpm_rsaencrypt_ctx;
struct tpm_rsaencrypt_ctx {
    const char *context_arg;
    tpm2_loaded_object key_context;
    TPM2B_PUBLIC_KEY_RSA message;
    char *output_path;
    char *input_path;
    TPMT_RSA_DECRYPT scheme;
    const char *scheme_str;
    TPM2B_DATA label;
};

static tpm_rsaencrypt_ctx ctx = {
    .context_arg = NULL,
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static tool_rc rsa_encrypt_and_save(ESYS_CONTEXT *context) {

    bool ret = false;
    TPM2B_PUBLIC_KEY_RSA *out_data = NULL;
    tool_rc rc;

    struct timeval t1, t2;
    float elapsedTime = 0.0f;

    // Open file and get its size
    FILE *f = fopen(ctx.input_path, "rb");
    if (!f) {
        LOG_ERR("Could not open file \"%s\"", ctx.input_path);
        return false;
    }

    const unsigned long MAX_FILE_SIZE = 60 * 1024;

    const int CHUNK_SIZE = 245;
    const int ENCRYPTED_CHUNK_SIZE = 256;

    BYTE *input_buffer = malloc(MAX_FILE_SIZE);
    BYTE *start_input_buffer = input_buffer;
    UINT16 count_bytes_read = MAX_FILE_SIZE;

    bool res = file_read_bytes_from_file(f,input_buffer,&count_bytes_read,ctx.input_path);
    const unsigned long FILE_SIZE = count_bytes_read;
    
    if(!res){
        LOG_ERR("Input file read failed");
    }
    LOG_INFO("File size: %lu, read bytes: %u", FILE_SIZE, count_bytes_read);

    const int FULL_CHUNKS = FILE_SIZE / CHUNK_SIZE;
    const int LAST_BYTES = FILE_SIZE - (FULL_CHUNKS * CHUNK_SIZE);
    unsigned long ENCRYPTED_FILE_SIZE = ((FULL_CHUNKS + 1) * ENCRYPTED_CHUNK_SIZE);
    BYTE *output_buffer = malloc(ENCRYPTED_FILE_SIZE);
    BYTE *start_output_buffer = output_buffer;

    gettimeofday(&t1, NULL);

    for (int i = 0; i <= FULL_CHUNKS; i++)
    {
        int size_of_bytes;

        if(i == FULL_CHUNKS){
            size_of_bytes = LAST_BYTES;
        } else {
            size_of_bytes = CHUNK_SIZE;
        }

        memcpy(ctx.message.buffer, input_buffer, size_of_bytes);
        ctx.message.size = size_of_bytes;

        rc = tpm2_rsa_encrypt(context, &ctx.key_context,
                &ctx.message, &ctx.scheme, &ctx.label, &out_data);

        if (rc != tool_rc_success) {
            return rc;
        }

        memcpy(output_buffer, out_data->buffer, out_data->size);

        output_buffer += ENCRYPTED_CHUNK_SIZE;
        input_buffer += CHUNK_SIZE;
    }

    gettimeofday(&t2, NULL);

    // compute and print the elapsed time in millisec
    elapsedTime += (t2.tv_sec - t1.tv_sec) * 1000.0;      // sec to ms
    elapsedTime += (t2.tv_usec - t1.tv_usec) / 1000.0;   // us to ms

    fclose(f); 

    f = ctx.output_path ? fopen(ctx.output_path, "wb+") : stdout;
    if (!f) {
        goto out;
    }

    ret = files_write_bytes(f, output_buffer, ENCRYPTED_FILE_SIZE);
    if (f != stdout) {
        fclose(f);
    }

out:
    free(out_data);
    free(start_input_buffer);
    free(start_output_buffer);

    LOG_INFO("Elapsed time (ms): %f", elapsedTime);
    
    return ret ? tool_rc_success : tool_rc_general_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.context_arg = value;
        break;
    case 'o':
        ctx.output_path = value;
        break;
    case 's':
        ctx.scheme_str = value;
        break;
    case 'l':
        return tpm2_util_get_label(value, &ctx.label);
    }
    return true;
}

static bool on_args(int argc, char **argv) {

    if (argc > 1) {
        LOG_ERR("Only supports one input file, got: %d", argc);
        return false;
    }

    ctx.input_path = argv[0];

    return true;
}

static bool tpm2_tool_onstart(tpm2_options **opts) {

    static const struct option topts[] = {
      {"output",      required_argument, NULL, 'o'},
      {"key-context", required_argument, NULL, 'c'},
      {"scheme",      required_argument, NULL, 's'},
      {"label",       required_argument, NULL, 'l'},
    };

    *opts = tpm2_options_new("o:c:s:l:", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *context) {

    if (!ctx.context_arg) {
        LOG_ERR("Expected option c");
        return tool_rc_option_error;
    }

    ctx.message.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    //bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
    //        ctx.input_path, &ctx.message.size, ctx.message.buffer);

    //if (!result) {
        //return tool_rc_general_error;
    //}

    /*
     * Load the decryption key
     */
    tool_rc rc = tpm2_util_object_load(context, ctx.context_arg, &ctx.key_context,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPM2B_PUBLIC *key_public_info = 0;
    rc = tpm2_readpublic(context, ctx.key_context.tr_handle, &key_public_info,
        NULL, NULL);
    if (rc != tool_rc_success) {
        goto out;
    }

    if (key_public_info->publicArea.type != TPM2_ALG_RSA) {
            LOG_ERR("Unsupported key type for RSA decryption.");
            rc = tool_rc_general_error;
            goto out;
    }

    /*
     * Get scheme information
     */
    if (ctx.scheme_str) {
        rc = tpm2_alg_util_handle_rsa_ext_alg(ctx.scheme_str, key_public_info);
        ctx.scheme.scheme =
            key_public_info->publicArea.parameters.rsaDetail.scheme.scheme;
        ctx.scheme.details.anySig.hashAlg =
            key_public_info->publicArea.parameters.rsaDetail.scheme.details.anySig.hashAlg;
    }

out:
    Esys_Free(key_public_info);

    return rc;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *context, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(context);
    if (rc != tool_rc_success) {
        return rc;
    }

    return rsa_encrypt_and_save(context);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("rsaencrypt", tpm2_tool_onstart, tpm2_tool_onrun, NULL, NULL)
