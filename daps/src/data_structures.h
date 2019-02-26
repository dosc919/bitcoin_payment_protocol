//
// Created by dominik on 27.09.17.
//

#ifndef DAPS_DATA_STRUCTURES_H
#define DAPS_DATA_STRUCTURES_H

#include <stdint.h>
#include <openssl/ec.h>

typedef struct _DapsPK_
{
    EC_KEY* pk_sign_; //public ECDSA key
    EC_KEY* pk_enc_; //public ElGamal key
    EC_POINT** c1_i_; // ElGamal
    EC_POINT** c2_i_; // encryption
    uint8_t** y_; //encryption of r_i and rho_i (see DapsSK)
    size_t n_; //maximum number of signatures
} DapsPK;

typedef struct _DapsSK_
{
    EC_KEY* sk_sign_; //secret ECDSA key
    BIGNUM** r_i_; //randomness for the ElGamal encryption
    BIGNUM** rho_i_;//randomness for the secret sharing
    size_t n_;//maximum number of signatures
} DapsSK;

typedef struct _DapsSignature_
{
    BIGNUM* z_; // share of the secret sign key
    BIGNUM* s_; // s = x * c + t of nizk
    EC_POINT* t1_; // g1 * t
    EC_POINT* t2_; // g2 * t
    uint8_t* sigma_; // ECDSA signature
    uint32_t sigma_length_;
} DapsSignature;

typedef struct _DapsMessage_
{
    uint32_t i_; //index of the message
    size_t p_length_;
    uint8_t* p_; //payload of the message
} DapsMessage;

#endif //DAPS_DATA_STRUCTURES_H
