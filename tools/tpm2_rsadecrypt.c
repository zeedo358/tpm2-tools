/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdlib.h>
#include <string.h>

#include "files.h"
#include "log.h"
#include "tpm2.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_options.h"

typedef struct tpm_rsadecrypt_ctx tpm_rsadecrypt_ctx;
struct tpm_rsadecrypt_ctx {
    struct {
        const char *ctx_path;
        const char *auth_str;
        tpm2_loaded_object object;
    } key;

    TPM2B_DATA label;
    TPM2B_PUBLIC_KEY_RSA cipher_text;
    char *input_path;
    char *output_file_path;

    TPMT_RSA_DECRYPT scheme;
    const char *scheme_str;

    char *cp_hash_path;
};

static tpm_rsadecrypt_ctx ctx = {
    .scheme = { .scheme = TPM2_ALG_RSAES }
};

static tool_rc rsa_decrypt_and_save(ESYS_CONTEXT *ectx) {

    TPM2B_PUBLIC_KEY_RSA *message = NULL;

    if (ctx.cp_hash_path) {
        TPM2B_DIGEST cp_hash = { .size = 0 };
        tool_rc rc = tpm2_rsa_decrypt(ectx, &ctx.key.object, &ctx.cipher_text,
            &ctx.scheme, &ctx.label, &message, &cp_hash);
        if (rc != tool_rc_success) {
            return rc;
        }

        bool result = files_save_digest(&cp_hash, ctx.cp_hash_path);
        if (!result) {
            rc = tool_rc_general_error;
        }

        return rc;
    }

    // Open file and get its size
    FILE *f = fopen(ctx.input_path, "rb");
    if (!f) {
        LOG_ERR("Could not open file \"%s\"", ctx.input_path);
        return false;
    }

    const unsigned long MAX_FILE_SIZE = 60 * 1024;

    const int CHUNK_SIZE = 256;
    const int DECRYPTED_CHUNK_SIZE = 245;

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
    unsigned long DECRYPTED_FILE_SIZE = ((FULL_CHUNKS + 1) * DECRYPTED_CHUNK_SIZE);
    BYTE *output_buffer = malloc(DECRYPTED_FILE_SIZE);
    BYTE *start_output_buffer = output_buffer;

    for (int i = 0; i <= FULL_CHUNKS; i++)
    {
        int size_of_bytes;

        if(i == FULL_CHUNKS){
            size_of_bytes = LAST_BYTES;
        } else {
            size_of_bytes = CHUNK_SIZE;
        }

        memcpy(ctx.cipher_text.buffer, input_buffer, size_of_bytes);
        ctx.cipher_text.size = size_of_bytes;

        tool_rc rc = tpm2_rsa_decrypt(ectx, &ctx.key.object, &ctx.cipher_text,
            &ctx.scheme, &ctx.label, &message, NULL);
        if (rc != tool_rc_success) {
            return rc;
        }

        memcpy(output_buffer, message->buffer, message->size);

        output_buffer += DECRYPTED_CHUNK_SIZE;
        input_buffer += CHUNK_SIZE;
    }

    fclose(f); 

    bool ret = false;
    f =
            ctx.output_file_path ? fopen(ctx.output_file_path, "wb+") : stdout;
    if (!f) {
        goto out;
    }

    ret = files_write_bytes(f, message->buffer, message->size);
    if (f != stdout) {
        fclose(f);
    }

out:
    free(message);
    free(start_input_buffer);
    free(start_output_buffer);

    return ret ? tool_rc_success : tool_rc_general_error;
}

static bool on_option(char key, char *value) {

    switch (key) {
    case 'c':
        ctx.key.ctx_path = value;
        break;
    case 'p':
        ctx.key.auth_str = value;
        break;
    case 'o': {
        ctx.output_file_path = value;
        break;
    }
    case 's':
        ctx.scheme_str = value;
        break;
    case 0:
        ctx.cp_hash_path = value;
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

    static struct option topts[] = {
      { "auth",        required_argument, NULL, 'p' },
      { "output",      required_argument, NULL, 'o' },
      { "key-context", required_argument, NULL, 'c' },
      { "scheme",      required_argument, NULL, 's' },
      { "label",       required_argument, NULL, 'l' },
      { "cphash",      required_argument, NULL,  0  },
    };

    *opts = tpm2_options_new("p:o:c:s:l:", ARRAY_LEN(topts), topts, on_option,
            on_args, 0);

    return *opts != NULL;
}

static tool_rc init(ESYS_CONTEXT *ectx) {

    if (!ctx.key.ctx_path) {
        LOG_ERR("Expected argument -c.");
        return tool_rc_option_error;
    }

    if (ctx.output_file_path && ctx.cp_hash_path) {
        LOG_ERR("Cannout decrypt when calculating cphash");
        return tool_rc_option_error;
    }

    /*
     * Load the decryption key
     */
    tool_rc rc = tpm2_util_object_load_auth(ectx, ctx.key.ctx_path,
        ctx.key.auth_str, &ctx.key.object, false,
        TPM2_HANDLES_FLAGS_TRANSIENT|TPM2_HANDLES_FLAGS_PERSISTENT);
    if (rc != tool_rc_success) {
        return rc;
    }

    TPM2B_PUBLIC *key_public_info = 0;
    rc = tpm2_readpublic(ectx, ctx.key.object.tr_handle, &key_public_info,
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

        if (rc != tool_rc_success) {
            goto out;
        }
    }

    /*
     * Get enc data blob
     */
    ctx.cipher_text.size = BUFFER_SIZE(TPM2B_PUBLIC_KEY_RSA, buffer);
    /*bool result = files_load_bytes_from_buffer_or_file_or_stdin(NULL,
            ctx.input_path, &ctx.cipher_text.size, ctx.cipher_text.buffer);
    if (!result) {
        rc = tool_rc_general_error;
    }*/

out:
    Esys_Free(key_public_info);

    return rc;
}

static tool_rc tpm2_tool_onrun(ESYS_CONTEXT *ectx, tpm2_option_flags flags) {

    UNUSED(flags);

    tool_rc rc = init(ectx);
    if (rc != tool_rc_success) {
        return rc;
    }

    return rsa_decrypt_and_save(ectx);
}

static tool_rc tpm2_tool_onstop(ESYS_CONTEXT *ectx) {
    UNUSED(ectx);
    return tpm2_session_close(&ctx.key.object.session);
}

// Register this tool with tpm2_tool.c
TPM2_TOOL_REGISTER("rsadecrypt", tpm2_tool_onstart, tpm2_tool_onrun, tpm2_tool_onstop, NULL)
