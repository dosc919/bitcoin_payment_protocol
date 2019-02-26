//
// Created by dominik on 02.10.17.
//

#ifndef DAPS_CONST_AND_ERROR_H
#define DAPS_CONST_AND_ERROR_H

#define DAPS_VERBOSE_ERROR 1

static const char* HKDF_SALT = "daps_salt\0";
static const char* HKDF_INFO = "daps_info\0";

static const char* STRING_SUCCESS = "Function executed successfully.";
static const char* STRING_OPENSSL_ERROR = "An error in the OpenSSL library occurred.";
static const char* STRING_OUT_OF_MEMORY = "The system ran out of memory.";

static const char* STRING_PK_NULL = "The public key is null.";
static const char* STRING_PK_NO_INIT = "The public key is not initialized correctly";
static const char* STRING_SK_NULL = "The secret key is null.";
static const char* STRING_SK_NO_INIT = "The secret key is not initialized correctly";
static const char* STRING_MSG_NULL = "The message is null.";
static const char* STRING_MSG_EMPTY = "The message is empty.";
static const char* STRING_MSG_INVALID = "The address in the message exceeds the maximum allowed address.";
static const char* STRING_SIGN_NULL = "The signature is null.";
static const char* STRING_SIGN_EMPTY = "The signature is empty.";

static const char* STRING_KEY_GEN_N_ZERO = "Cannot generate keys, because parameter n is zero.";

static const char* STRING_VERIFY_SIGNATURE_INVALID = "The signature is not valid.";

static const char* STRING_EXTRACT_ADDRESS_MISMATCH = "Cannot extract secret key, because the addresses of the messages "
                                                     "do not match.";
static const char* STRING_EXTRACT_PAYLOAD_MATCH = "Cannot extract secret key, because the payloads are the same.";

static const char* STRING_UNKNOWN_ERROR = "An unknown error occurred.";

typedef enum _ErrorCodes_
{
    SUCCESS = 0,
    OPENSSL_ERROR,
    OUT_OF_MEMORY,

    PK_NULL,
    PK_NO_INIT,

    SK_NULL,
    SK_NO_INIT,

    MSG_NULL,
    MSG_EMPTY,
    MSG_INVALID,

    SIGN_NULL,
    SIGN_EMPTY,

    KEY_GEN_N_ZERO,
    VERIFY_SIGNATURE_INVALID,

    EXTRACT_ADDRESS_MISMATCH,
    EXTRACT_PAYLOAD_MATCH,
} ErrorCodes;

static inline const char* getErrorString(ErrorCodes error)
{
    switch(error)
    {
        case SUCCESS:
            return STRING_SUCCESS;
        case OPENSSL_ERROR:
            return STRING_OPENSSL_ERROR;
        case OUT_OF_MEMORY:
            return STRING_OUT_OF_MEMORY;
        case PK_NULL:
            return STRING_PK_NULL;
        case PK_NO_INIT:
            return STRING_PK_NO_INIT;
        case SK_NULL:
            return STRING_SK_NULL;
        case SK_NO_INIT:
            return STRING_SK_NO_INIT;
        case MSG_NULL:
            return STRING_MSG_NULL;
        case MSG_EMPTY:
            return STRING_MSG_EMPTY;
        case MSG_INVALID:
            return STRING_MSG_INVALID;
        case SIGN_NULL:
            return STRING_SIGN_NULL;
        case SIGN_EMPTY:
            return STRING_SIGN_EMPTY;
        case KEY_GEN_N_ZERO:
            return STRING_KEY_GEN_N_ZERO;
        case VERIFY_SIGNATURE_INVALID:
            return STRING_VERIFY_SIGNATURE_INVALID;
        case EXTRACT_ADDRESS_MISMATCH:
            return STRING_EXTRACT_ADDRESS_MISMATCH;
        case EXTRACT_PAYLOAD_MATCH:
            return STRING_EXTRACT_PAYLOAD_MATCH;
        default:
            return STRING_UNKNOWN_ERROR;
    }
}

#define CHECK_OPENSSL_ERROR(function, comp_op, expected_val) do{\
    if((function) comp_op expected_val)\
    {\
        if(DAPS_VERBOSE_ERROR)\
        {\
            fprintf(stderr, "In file: %s, line %d :\n", __FILE__, __LINE__);\
            fprintf(stderr, "%s\n", ERR_error_string(ERR_get_error(), NULL));\
        }\
        \
        return OPENSSL_ERROR;\
    }\
} while(0)

#endif //DAPS_CONST_AND_ERROR_H
