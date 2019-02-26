//
// Created by dominik on 28.09.17.
//

#include "daps.h"
#include <openssl/err.h>
#include <openssl/sha.h>
#include <string.h>
#include <openssl/kdf.h>

#define CURVE NID_secp256k1

//----------------------------------------------------------------------------------------------------------------------
//main functions
//----------------------------------------------------------------------------------------------------------------------

ErrorCodes dapsKeyGen(DapsSK* sk, DapsPK* pk, uint32_t n)
{
    //sanity checks
    if(n == 0)
        return KEY_GEN_N_ZERO;

    if(sk == NULL)
        return SK_NULL;

    if(pk == NULL)
        return PK_NULL;

    //generate EC_KEY signing pair
    CHECK_OPENSSL_ERROR(sk->sk_sign_ = EC_KEY_new_by_curve_name(CURVE), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_generate_key(sk->sk_sign_), !=, 1);

    //extract public signing key
    const EC_POINT* pk_sign = NULL;
    const EC_GROUP* grp = NULL;
    CHECK_OPENSSL_ERROR(pk_sign = EC_KEY_get0_public_key(sk->sk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(grp = EC_KEY_get0_group(sk->sk_sign_), ==, NULL);

    //set up EC_KEY (pk) with a public signing key only
    CHECK_OPENSSL_ERROR(pk->pk_sign_ = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(pk->pk_sign_, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_set_public_key(pk->pk_sign_, pk_sign), !=, 1);

    //generate EC_KEY encryption pair with the same generator
    EC_KEY* sk_enc = NULL;
    const EC_POINT* pk_enc = NULL;
    CHECK_OPENSSL_ERROR(sk_enc = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(sk_enc, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_generate_key(sk_enc), !=, 1);

    //extract public encryption key
    CHECK_OPENSSL_ERROR(pk_enc = EC_KEY_get0_public_key(sk_enc), ==, NULL);

    //set up EC_KEY(pk) with a public encryption key only
    CHECK_OPENSSL_ERROR(pk->pk_enc_ = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(pk->pk_enc_, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_set_public_key(pk->pk_enc_, pk_enc), !=, 1);

    //set up random vars (r_i and rho_i) and encryption for secret sharing verification (c1_i, c2_i)
    CHECK_OPENSSL_ERROR(sk->r_i_ = OPENSSL_malloc(n * sizeof(BIGNUM*)), ==, NULL);
    CHECK_OPENSSL_ERROR(sk->rho_i_ = OPENSSL_malloc(n * sizeof(BIGNUM*)), ==, NULL);
    CHECK_OPENSSL_ERROR(pk->c1_i_ = OPENSSL_malloc(n * sizeof(EC_POINT*)), ==, NULL);
    CHECK_OPENSSL_ERROR(pk->c2_i_ = OPENSSL_malloc(n * sizeof(EC_POINT*)), ==, NULL);

    //get group order - 1 for random number generation
    const BIGNUM* grp_order;
    BIGNUM* grp_order_sub1;
    CHECK_OPENSSL_ERROR(grp_order = EC_GROUP_get0_order(grp), ==, NULL);
    CHECK_OPENSSL_ERROR(grp_order_sub1 = BN_dup(grp_order), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_sub_word(grp_order_sub1, 1), !=, 1);

    for(int i = 0; i < n; ++i)
    {
        //get r
        CHECK_OPENSSL_ERROR(sk->r_i_[i] = BN_new(), ==, NULL);
        CHECK_OPENSSL_ERROR(BN_rand_range(sk->r_i_[i], grp_order_sub1), !=, 1);
        CHECK_OPENSSL_ERROR(BN_add_word(sk->r_i_[i], 1), !=, 1);

        //get g * r (= c1_i)
        CHECK_OPENSSL_ERROR(pk->c1_i_[i] = EC_POINT_new(grp), ==, NULL);
        CHECK_OPENSSL_ERROR(EC_POINT_mul(grp, pk->c1_i_[i], sk->r_i_[i], NULL, NULL, NULL), !=, 1);

        //get rho
        CHECK_OPENSSL_ERROR(sk->rho_i_[i] = BN_new(), ==, NULL);
        CHECK_OPENSSL_ERROR(BN_rand_range(sk->rho_i_[i], grp_order_sub1), !=, 1);
        CHECK_OPENSSL_ERROR(BN_add_word(sk->rho_i_[i], 1), !=, 1);

        //get pk * r + g * rho (= c2_i)
        CHECK_OPENSSL_ERROR(pk->c2_i_[i] = EC_POINT_new(grp), ==, NULL);
        CHECK_OPENSSL_ERROR(EC_POINT_mul(grp, pk->c2_i_[i], sk->rho_i_[i], pk_enc, sk->r_i_[i], NULL), !=, 1);
    }

    sk->n_ = n;
    pk->n_ = n;

    //convert secret signing key to char array
    const BIGNUM* sk_sign_bn;
    uint8_t* sk_sign_char;
    size_t sk_sign_length;
    int size;
    CHECK_OPENSSL_ERROR(sk_sign_bn = EC_KEY_get0_private_key(sk->sk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(size = BN_num_bytes(sk_sign_bn), <=, 0);
    sk_sign_length = (size_t)size;
    CHECK_OPENSSL_ERROR(sk_sign_char = OPENSSL_malloc(sk_sign_length), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bn2bin(sk_sign_bn, sk_sign_char), <=, 0);

    //set up hkdf
    EVP_PKEY_CTX* pctx;
    CHECK_OPENSSL_ERROR(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL), ==, NULL);
    CHECK_OPENSSL_ERROR(EVP_PKEY_derive_init(pctx), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set1_hkdf_salt(pctx, HKDF_SALT, strlen(HKDF_SALT)), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_add1_hkdf_info(pctx, HKDF_INFO, strlen(HKDF_INFO)), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set1_hkdf_key(pctx, sk_sign_char, sk_sign_length), !=, 1);

    int bn_max_length;
    size_t bn_max_length_unsigned;
    CHECK_OPENSSL_ERROR(bn_max_length = BN_num_bytes(grp_order), <=, 0);
    bn_max_length_unsigned = (size_t)bn_max_length;
    CHECK_OPENSSL_ERROR(pk->y_ = OPENSSL_zalloc(2 * n * sizeof(uint8_t*)), ==, NULL);

    uint8_t* tmp;
    CHECK_OPENSSL_ERROR(tmp = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);

    //get y
    for(int i = 0; i < n; ++i)
    {
        //convert r to char array
        CHECK_OPENSSL_ERROR(BN_bn2binpad(sk->r_i_[i], tmp, bn_max_length), !=, bn_max_length);

        //get part of H(x) and xor with r
        CHECK_OPENSSL_ERROR(pk->y_[i] = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);
        CHECK_OPENSSL_ERROR(EVP_PKEY_derive(pctx, pk->y_[i], &bn_max_length_unsigned), !=, 1);
        OPENSSL_assert(bn_max_length_unsigned == (size_t)bn_max_length);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            pk->y_[i][j] ^= tmp[j];

        //convert rho to char array
        CHECK_OPENSSL_ERROR(BN_bn2binpad(sk->rho_i_[i], tmp, bn_max_length), !=, bn_max_length);

        //get part of H(x) and xor with rho
        CHECK_OPENSSL_ERROR(pk->y_[n + i] = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);
        CHECK_OPENSSL_ERROR(EVP_PKEY_derive(pctx, pk->y_[n + i], &bn_max_length_unsigned), !=, 1);
        OPENSSL_assert(bn_max_length_unsigned == (size_t)bn_max_length);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            pk->y_[n + i][j] ^= tmp[j];
    }

    //clean up
    EC_KEY_free(sk_enc);
    EVP_PKEY_CTX_free(pctx);
    BN_free(grp_order_sub1);
    OPENSSL_free(sk_sign_char);
    OPENSSL_free(tmp);

    return SUCCESS;
}

ErrorCodes dapsKeyGenECDSAExternal(DapsSK* sk, DapsPK* pk, uint32_t n, const uint8_t* sk_ecdsa)
{
    //sanity checks
    if(n == 0)
        return KEY_GEN_N_ZERO;

    if(sk == NULL)
        return SK_NULL;

    if(pk == NULL)
        return PK_NULL;

    //convert sk_ecdsa to bignum
    BIGNUM* sk_sign;
    CHECK_OPENSSL_ERROR(sk_sign = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bin2bn(sk_ecdsa, 32, sk_sign), ==, NULL);

    BN_CTX* bn_ctx;
    CHECK_OPENSSL_ERROR(bn_ctx = BN_CTX_new(), ==, NULL);

    //setup group for bitcoin
    EC_GROUP* grp;
    EC_POINT* generator;
    const BIGNUM* order;
    BIGNUM* x_coord;
    uint8_t x_bin[32] = {0x79, 0xBE, 0x66, 0x7E, 0xF9, 0xDC, 0xBB, 0xAC, 0x55, 0xA0, 0x62, 0x95, 0xCE, 0x87, 0x0B, 0x07,
                         0x02, 0x9B, 0xFC, 0xDB, 0x2D, 0xCE, 0x28, 0xD9, 0x59, 0xF2, 0x81, 0x5B, 0x16, 0xF8, 0x17, 0x98};
    CHECK_OPENSSL_ERROR(grp = EC_GROUP_new_by_curve_name(CURVE), ==, NULL);
    CHECK_OPENSSL_ERROR(generator = EC_POINT_new(grp), ==, NULL);
    CHECK_OPENSSL_ERROR(x_coord = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bin2bn(x_bin, 32, x_coord), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_POINT_set_compressed_coordinates_GFp(grp, generator, x_coord, 0, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(order = EC_GROUP_get0_order(grp), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_GROUP_set_generator(grp, generator, order, BN_value_one()), !=, 1);

    //set EC_KEY signing pair
    CHECK_OPENSSL_ERROR(sk->sk_sign_ = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(sk->sk_sign_, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_set_private_key(sk->sk_sign_, sk_sign), !=, 1);

    //calculate and set public signing key
    EC_POINT* pk_sign = NULL;
    CHECK_OPENSSL_ERROR(pk_sign = EC_POINT_new(grp), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_POINT_mul(grp, pk_sign, sk_sign, NULL, NULL, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(pk->pk_sign_ = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(pk->pk_sign_, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_set_public_key(pk->pk_sign_, pk_sign), !=, 1);

    //generate EC_KEY encryption pair with the same generator
    EC_KEY* sk_enc = NULL;
    const EC_POINT* pk_enc = NULL;
    CHECK_OPENSSL_ERROR(sk_enc = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(sk_enc, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_generate_key(sk_enc), !=, 1);

    //extract public encryption key
    CHECK_OPENSSL_ERROR(pk_enc = EC_KEY_get0_public_key(sk_enc), ==, NULL);

    //set up EC_KEY(pk) with a public encryption key only
    CHECK_OPENSSL_ERROR(pk->pk_enc_ = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(pk->pk_enc_, grp), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_set_public_key(pk->pk_enc_, pk_enc), !=, 1);

    //set up random vars (r_i and rho_i) and encryption for secret sharing verification (c1_i, c2_i)
    CHECK_OPENSSL_ERROR(sk->r_i_ = OPENSSL_malloc(n * sizeof(BIGNUM*)), ==, NULL);
    CHECK_OPENSSL_ERROR(sk->rho_i_ = OPENSSL_malloc(n * sizeof(BIGNUM*)), ==, NULL);
    CHECK_OPENSSL_ERROR(pk->c1_i_ = OPENSSL_malloc(n * sizeof(EC_POINT*)), ==, NULL);
    CHECK_OPENSSL_ERROR(pk->c2_i_ = OPENSSL_malloc(n * sizeof(EC_POINT*)), ==, NULL);

    //get group order - 1 for random number generation
    const BIGNUM* grp_order;
    BIGNUM* grp_order_sub1;
    CHECK_OPENSSL_ERROR(grp_order = EC_GROUP_get0_order(grp), ==, NULL);
    CHECK_OPENSSL_ERROR(grp_order_sub1 = BN_dup(grp_order), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_sub_word(grp_order_sub1, 1), !=, 1);

    for(int i = 0; i < n; ++i)
    {
        //get r
        CHECK_OPENSSL_ERROR(sk->r_i_[i] = BN_new(), ==, NULL);
        CHECK_OPENSSL_ERROR(BN_rand_range(sk->r_i_[i], grp_order_sub1), !=, 1);
        CHECK_OPENSSL_ERROR(BN_add_word(sk->r_i_[i], 1), !=, 1);

        //get g * r (= c1_i)
        CHECK_OPENSSL_ERROR(pk->c1_i_[i] = EC_POINT_new(grp), ==, NULL);
        CHECK_OPENSSL_ERROR(EC_POINT_mul(grp, pk->c1_i_[i], sk->r_i_[i], NULL, NULL, NULL), !=, 1);

        //get rho
        CHECK_OPENSSL_ERROR(sk->rho_i_[i] = BN_new(), ==, NULL);
        CHECK_OPENSSL_ERROR(BN_rand_range(sk->rho_i_[i], grp_order_sub1), !=, 1);
        CHECK_OPENSSL_ERROR(BN_add_word(sk->rho_i_[i], 1), !=, 1);

        //get pk * r + g * rho (= c2_i)
        CHECK_OPENSSL_ERROR(pk->c2_i_[i] = EC_POINT_new(grp), ==, NULL);
        CHECK_OPENSSL_ERROR(EC_POINT_mul(grp, pk->c2_i_[i], sk->rho_i_[i], pk_enc, sk->r_i_[i], NULL), !=, 1);
    }

    sk->n_ = n;
    pk->n_ = n;

    //convert secret signing key to char array
    const BIGNUM* sk_sign_bn;
    uint8_t* sk_sign_char;
    size_t sk_sign_length;
    int size;
    CHECK_OPENSSL_ERROR(sk_sign_bn = EC_KEY_get0_private_key(sk->sk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(size = BN_num_bytes(sk_sign_bn), <=, 0);
    sk_sign_length = (size_t)size;
    CHECK_OPENSSL_ERROR(sk_sign_char = OPENSSL_malloc(sk_sign_length), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bn2bin(sk_sign_bn, sk_sign_char), <=, 0);

    //set up hkdf
    EVP_PKEY_CTX* pctx;
    CHECK_OPENSSL_ERROR(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL), ==, NULL);
    CHECK_OPENSSL_ERROR(EVP_PKEY_derive_init(pctx), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set1_hkdf_salt(pctx, HKDF_SALT, strlen(HKDF_SALT)), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_add1_hkdf_info(pctx, HKDF_INFO, strlen(HKDF_INFO)), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set1_hkdf_key(pctx, sk_sign_char, sk_sign_length), !=, 1);

    int bn_max_length;
    size_t bn_max_length_unsigned;
    CHECK_OPENSSL_ERROR(bn_max_length = BN_num_bytes(grp_order), <=, 0);
    bn_max_length_unsigned = (size_t)bn_max_length;
    CHECK_OPENSSL_ERROR(pk->y_ = OPENSSL_zalloc(2 * n * sizeof(uint8_t*)), ==, NULL);

    uint8_t* tmp;
    CHECK_OPENSSL_ERROR(tmp = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);

    //get y
    for(int i = 0; i < n; ++i)
    {
        //convert r to char array
        CHECK_OPENSSL_ERROR(BN_bn2binpad(sk->r_i_[i], tmp, bn_max_length), !=, bn_max_length);

        //get part of H(x) and xor with r
        CHECK_OPENSSL_ERROR(pk->y_[i] = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);
        CHECK_OPENSSL_ERROR(EVP_PKEY_derive(pctx, pk->y_[i], &bn_max_length_unsigned), !=, 1);
        OPENSSL_assert(bn_max_length_unsigned == (size_t)bn_max_length);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            pk->y_[i][j] ^= tmp[j];

        //convert rho to char array
        CHECK_OPENSSL_ERROR(BN_bn2binpad(sk->rho_i_[i], tmp, bn_max_length), !=, bn_max_length);

        //get part of H(x) and xor with rho
        CHECK_OPENSSL_ERROR(pk->y_[n + i] = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);
        CHECK_OPENSSL_ERROR(EVP_PKEY_derive(pctx, pk->y_[n + i], &bn_max_length_unsigned), !=, 1);
        OPENSSL_assert(bn_max_length_unsigned == (size_t)bn_max_length);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            pk->y_[n + i][j] ^= tmp[j];
    }

    //clean up
    EC_KEY_free(sk_enc);
    EC_GROUP_free(grp);
    EC_POINT_free(generator);
    EC_POINT_free(pk_sign);
    EVP_PKEY_CTX_free(pctx);
    BN_CTX_free(bn_ctx);
    BN_free(sk_sign);
    BN_free(x_coord);
    BN_free(grp_order_sub1);
    OPENSSL_free(sk_sign_char);
    OPENSSL_free(tmp);

    return SUCCESS;
}

ErrorCodes dapsSign(DapsSignature* sign, DapsSK* sk, DapsPK* pk, DapsMessage* m)
{
    //sanity checks
    if(sign == NULL)
        return SIGN_NULL;

    if(sk == NULL)
        return SK_NULL;

    if(sk->sk_sign_ == NULL || sk->r_i_ == NULL || sk->rho_i_ == NULL || sk->n_ == 0)
        return SK_NO_INIT;

    if(m == NULL)
        return MSG_NULL;

    if(m->p_ == NULL || m->p_length_ == 0)
        return MSG_EMPTY;

    if(m->i_ >= sk->n_)
        return MSG_INVALID;

    //create message digest
    SHA256_CTX sha_ctx;
    uint8_t* md = NULL;
    CHECK_OPENSSL_ERROR(md = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256_Init(&sha_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, m->p_, m->p_length_), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, &(m->i_), sizeof(m->i_)), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Final(md, &sha_ctx), !=, 1);

    //create signature
    uint32_t sign_size;
    CHECK_OPENSSL_ERROR(ECDSA_sign(0, md, SHA256_DIGEST_LENGTH, sign->sigma_, &sign_size, sk->sk_sign_), !=, 1);
    if(sign_size > sign->sigma_length_)
        return OPENSSL_ERROR;

    sign->sigma_length_ = sign_size;

    //get group and group order
    const EC_GROUP* group;
    const BIGNUM* grp_order;
    CHECK_OPENSSL_ERROR(group = EC_KEY_get0_group(sk->sk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(grp_order = EC_GROUP_get0_order(group), ==, NULL);

    //get digest of p and convert to bignum
    uint8_t* p_hash_char = NULL;
    BIGNUM* p_bn;
    CHECK_OPENSSL_ERROR(p_hash_char = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256(m->p_, m->p_length_, p_hash_char), ==, NULL);
    CHECK_OPENSSL_ERROR(p_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bin2bn(p_hash_char, SHA256_DIGEST_LENGTH, p_bn), ==, NULL);

    //create share of sk_sign
    const BIGNUM* sk_sign;
    BN_CTX* bn_ctx;
    CHECK_OPENSSL_ERROR(bn_ctx = BN_CTX_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(sk_sign = EC_KEY_get0_private_key(sk->sk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_mod_mul(sign->z_, sk->rho_i_[m->i_], p_bn, grp_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_mod_add(sign->z_, sign->z_, sk_sign, grp_order, bn_ctx), !=, 1);

    //get group order - 1 for random number generation
    BIGNUM* grp_order_sub1;
    CHECK_OPENSSL_ERROR(grp_order_sub1 = BN_dup(grp_order), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_sub_word(grp_order_sub1, 1), !=, 1);


    //create nizk proof for r_i
    uint8_t* c_char;
    BIGNUM* c_bn;
    uint8_t* g_t_char;
    size_t g_t_length;
    uint8_t* pk_t_char;
    size_t pk_t_length;
    BIGNUM* t_bn;

    CHECK_OPENSSL_ERROR(c_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(t_bn = BN_new(), ==, NULL);

    //create random number t
    CHECK_OPENSSL_ERROR(BN_rand_range(t_bn, grp_order_sub1), !=, 1);
    CHECK_OPENSSL_ERROR(BN_add_word(t_bn, 1), !=, 1);

    //calculate g * t and convert to char array
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, sign->t1_, t_bn, NULL, NULL, bn_ctx), !=, 1);
    point_conversion_form_t conversion_form = EC_GROUP_get_point_conversion_form(group);
    CHECK_OPENSSL_ERROR(g_t_length = EC_POINT_point2buf(group, sign->t1_, conversion_form, &g_t_char, NULL), <=, 0);

    //calculate pk_sign * t and convert to char array
    const EC_POINT* pk_sign;
    CHECK_OPENSSL_ERROR(pk_sign = EC_KEY_get0_public_key(pk->pk_enc_), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, sign->t2_, NULL, pk_sign, t_bn, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(pk_t_length = EC_POINT_point2buf(group, sign->t2_, conversion_form, &pk_t_char, NULL), <=, 0);

    //create challenge c and convert to BIGNUM
    CHECK_OPENSSL_ERROR(c_char = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256_Init(&sha_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, g_t_char, g_t_length), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, pk_t_char, pk_t_length), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Final(c_char, &sha_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_bin2bn(c_char, SHA256_DIGEST_LENGTH, c_bn), ==, NULL);

    //calculate s = c * r_i + t
    CHECK_OPENSSL_ERROR(BN_mod_mul(sign->s_, c_bn, sk->r_i_[m->i_], grp_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_mod_add(sign->s_, sign->s_, t_bn, grp_order, bn_ctx), !=, 1);

    //clean up
    OPENSSL_free(md);
    OPENSSL_free(p_hash_char);
    OPENSSL_free(c_char);
    OPENSSL_free(g_t_char);
    OPENSSL_free(pk_t_char);
    BN_free(c_bn);
    BN_free(p_bn);
    BN_free(t_bn);
    BN_CTX_free(bn_ctx);
    BN_free(grp_order_sub1);

    return SUCCESS;
}

ErrorCodes dapsVerify(DapsPK* pk, DapsMessage* m, DapsSignature* sign)
{
    //sanity checks
    if(m == NULL)
        return MSG_NULL;

    if(m->p_ == NULL || m->p_length_ == 0)
        return MSG_EMPTY;

    if(m->i_ >= pk->n_)
        return MSG_INVALID;

    if(pk == NULL)
        return PK_NULL;

    if(pk->pk_sign_ == NULL || pk->pk_enc_ == NULL || pk->c1_i_ == NULL || pk->c2_i_ == NULL ||
       pk->y_ == NULL || pk->n_ == 0 || pk->c1_i_[m->i_] == NULL || pk->c2_i_[m->i_] == NULL)
        return PK_NO_INIT;

    if(sign == NULL)
        return SIGN_NULL;

    if(sign->sigma_ == NULL || sign->s_ == NULL ||  sign->t1_ == NULL || sign->t2_ == NULL || sign->z_ == NULL)
        return SIGN_EMPTY;

    //create message digest
    SHA256_CTX sha_ctx;
    uint8_t* md = NULL;
    CHECK_OPENSSL_ERROR(md = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256_Init(&sha_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, m->p_, m->p_length_), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, &(m->i_), sizeof(m->i_)), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Final(md, &sha_ctx), !=, 1);

    //verify signature
    int valid = ECDSA_verify(0, md, SHA256_DIGEST_LENGTH, sign->sigma_, sign->sigma_length_, pk->pk_sign_) == 1;

    //get group and group order
    const EC_GROUP* group;
    const BIGNUM* grp_order;
    CHECK_OPENSSL_ERROR(group = EC_KEY_get0_group(pk->pk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(grp_order = EC_GROUP_get0_order(group), ==, NULL);

    //get digest of p and convert to bignum
    uint8_t* p_hash_char = NULL;
    BIGNUM* p_bn;
    CHECK_OPENSSL_ERROR(p_hash_char = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256(m->p_, m->p_length_, p_hash_char), ==, NULL);
    CHECK_OPENSSL_ERROR(p_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bin2bn(p_hash_char, SHA256_DIGEST_LENGTH, p_bn), ==, NULL);

    //create context for BIGNUM operations
    BN_CTX* bn_ctx;
    CHECK_OPENSSL_ERROR(bn_ctx = BN_CTX_new(), ==, NULL);

    //calculate c2'
    EC_POINT* tmp;
    EC_POINT* c2_p;
    BIGNUM* p_inv_bn;
    const EC_POINT* pk_sign;
    const EC_POINT* pk_enc;
    CHECK_OPENSSL_ERROR(tmp = EC_POINT_new(group), ==, NULL);
    CHECK_OPENSSL_ERROR(c2_p = EC_POINT_new(group), ==, NULL);
    CHECK_OPENSSL_ERROR(p_inv_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(pk_sign = EC_KEY_get0_public_key(pk->pk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(pk_enc = EC_KEY_get0_public_key(pk->pk_enc_), ==, NULL);

    //get inverse of g * z
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, tmp, sign->z_, NULL, NULL, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_invert(group, tmp, NULL), !=, 1);
    //get inverse of p
    CHECK_OPENSSL_ERROR(BN_mod_inverse(p_inv_bn, p_bn, grp_order, bn_ctx), ==, NULL);
    //calculate (pk_sign - g * z) * (1 / p) + c2 (= c2')
    CHECK_OPENSSL_ERROR(EC_POINT_add(group, tmp, pk_sign, tmp, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, tmp, NULL, tmp, p_inv_bn, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_add(group, c2_p, tmp, pk->c2_i_[m->i_], NULL), !=, 1);

    //check nizk
    EC_POINT* g_s_1;
    EC_POINT* g_s_2;
    uint8_t* c_char;
    BIGNUM* c_bn;
    uint8_t* g_t_char;
    size_t g_t_length;
    uint8_t* pk_t_char;
    size_t pk_t_length;

    CHECK_OPENSSL_ERROR(c_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(g_s_1 = EC_POINT_new(group), ==, NULL);
    CHECK_OPENSSL_ERROR(g_s_2 = EC_POINT_new(group), ==, NULL);

    //convert g * t and pk_sign * t to char array
    point_conversion_form_t conversion_form = EC_GROUP_get_point_conversion_form(group);
    CHECK_OPENSSL_ERROR(g_t_length = EC_POINT_point2buf(group, sign->t1_, conversion_form, &g_t_char, NULL), <=, 0);
    CHECK_OPENSSL_ERROR(pk_t_length = EC_POINT_point2buf(group, sign->t2_, conversion_form, &pk_t_char, NULL), <=, 0);

    //create challenge c
    CHECK_OPENSSL_ERROR(c_char = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256_Init(&sha_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, g_t_char, g_t_length), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Update(&sha_ctx, pk_t_char, pk_t_length), !=, 1);
    CHECK_OPENSSL_ERROR(SHA256_Final(c_char, &sha_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_bin2bn(c_char, SHA256_DIGEST_LENGTH, c_bn), ==, NULL);

    //check if g * (c * r_i + t) == g * s
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, g_s_1, NULL, pk->c1_i_[m->i_], c_bn, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_add(group, g_s_1, g_s_1, sign->t1_, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, g_s_2, sign->s_, NULL, NULL, NULL), !=, 1);
    valid &= EC_POINT_cmp(group, g_s_1, g_s_2, NULL) == 0;

    EC_POINT* pk_s_1;
    EC_POINT* pk_s_2;
    CHECK_OPENSSL_ERROR(pk_s_1 = EC_POINT_new(group), ==, NULL);
    CHECK_OPENSSL_ERROR(pk_s_2 = EC_POINT_new(group), ==, NULL);

    //check if pk * (c * r_i + t) == pk * s
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, pk_s_1, NULL, c2_p, c_bn, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_add(group, pk_s_1, pk_s_1, sign->t2_, NULL), !=, 1);
    CHECK_OPENSSL_ERROR(EC_POINT_mul(group, pk_s_2, NULL, pk_enc, sign->s_, NULL), !=, 1);
    valid &= EC_POINT_cmp(group, pk_s_1, pk_s_2, NULL) == 0;

    //clean up
    OPENSSL_free(md);
    OPENSSL_free(p_hash_char);
    OPENSSL_free(c_char);
    OPENSSL_free(g_t_char);
    OPENSSL_free(pk_t_char);
    EC_POINT_free(tmp);
    EC_POINT_free(c2_p);
    EC_POINT_free(g_s_1);
    EC_POINT_free(g_s_2);
    EC_POINT_free(pk_s_1);
    EC_POINT_free(pk_s_2);
    BN_free(c_bn);
    BN_free(p_bn);
    BN_free(p_inv_bn);
    BN_CTX_free(bn_ctx);

    if(valid == 1)
        return SUCCESS;
    else if(valid == 0)
        return VERIFY_SIGNATURE_INVALID;
    else
        return OPENSSL_ERROR;
}

ErrorCodes dapsExtr(DapsSK* sk, DapsPK* pk, DapsMessage* m1, DapsMessage* m2, DapsSignature* sign1, DapsSignature* sign2)
{
    //sanity checks
    if(sk == NULL)
        return SK_NULL;

    if(m1 == NULL)
        return MSG_NULL;

    if(m1->p_ == NULL || m1->p_length_ == 0)
        return MSG_EMPTY;

    if(m1->i_ >= pk->n_)
        return MSG_INVALID;

    if(m2 == NULL)
        return MSG_NULL;

    if(m2->p_ == NULL || m2->p_length_ == 0)
        return MSG_EMPTY;

    if(m2->i_ >= pk->n_)
        return MSG_INVALID;

    if(pk == NULL)
        return PK_NULL;

    if(pk->pk_sign_ == NULL || pk->pk_enc_ == NULL || pk->c1_i_ == NULL || pk->c2_i_ == NULL ||
       pk->y_ == NULL || pk->n_ == 0 || pk->c1_i_[m1->i_] == NULL || pk->c2_i_[m1->i_] == NULL)
        return PK_NO_INIT;

    if(sign1 == NULL)
        return SIGN_NULL;

    if(sign1->sigma_ == NULL || sign1->s_ == NULL ||  sign1->t1_ == NULL ||  sign1->t2_ == NULL || sign1->z_ == NULL)
        return SIGN_EMPTY;

    if(sign2 == NULL)
        return SIGN_NULL;

    if(sign2->sigma_ == NULL || sign2->s_ == NULL ||  sign2->t1_ == NULL ||  sign2->t2_ == NULL || sign2->z_ == NULL)
        return SIGN_EMPTY;

    //check requirements
    if(m1->i_ != m2->i_)
        return EXTRACT_ADDRESS_MISMATCH;

    if((m1->p_length_ == m2->p_length_) && !memcmp(m1->p_, m2->p_, m1->p_length_))
        return EXTRACT_PAYLOAD_MATCH;

    if(dapsVerify(pk, m1, sign1) != SUCCESS)
        return VERIFY_SIGNATURE_INVALID;

    if(dapsVerify(pk, m2, sign2) != SUCCESS)
        return VERIFY_SIGNATURE_INVALID;

    //get digest of p and convert to bignum
    uint8_t* p1_char = NULL;
    BIGNUM* p1_bn;
    CHECK_OPENSSL_ERROR(p1_char = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256(m1->p_, m1->p_length_, p1_char), ==, NULL);
    CHECK_OPENSSL_ERROR(p1_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bin2bn(p1_char, SHA256_DIGEST_LENGTH, p1_bn), ==, NULL);

    uint8_t* p2_char = NULL;
    BIGNUM* p2_bn;
    CHECK_OPENSSL_ERROR(p2_char = OPENSSL_malloc(SHA256_DIGEST_LENGTH), ==, NULL);
    CHECK_OPENSSL_ERROR(SHA256(m2->p_, m2->p_length_, p2_char), ==, NULL);
    CHECK_OPENSSL_ERROR(p2_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bin2bn(p2_char, SHA256_DIGEST_LENGTH, p2_bn), ==, NULL);

    //create context for BIGNUM operations
    BN_CTX* bn_ctx;
    CHECK_OPENSSL_ERROR(bn_ctx = BN_CTX_new(), ==, NULL);

    //get group order
    const EC_GROUP* group;
    const BIGNUM* group_order;
    CHECK_OPENSSL_ERROR(group = EC_KEY_get0_group(pk->pk_sign_), ==, NULL);
    CHECK_OPENSSL_ERROR(group_order = EC_GROUP_get0_order(group), ==, NULL);

    //calc sk_part1 = z1 * p2 / (p2 - p1)
    BIGNUM* sk_part1;
    CHECK_OPENSSL_ERROR(sk_part1 = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_mod_sub(sk_part1, p2_bn, p1_bn, group_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_mod_inverse(sk_part1, sk_part1, group_order, bn_ctx), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_mod_mul(sk_part1, sk_part1, p2_bn, group_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_mod_mul(sk_part1, sk_part1, sign1->z_, group_order, bn_ctx), !=, 1);

    //calc sk_part2 = z2 * p1 / (p1 - p2)
    BIGNUM* sk_part2;
    CHECK_OPENSSL_ERROR(sk_part2 = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_mod_sub(sk_part2, p1_bn, p2_bn, group_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_mod_inverse(sk_part2, sk_part2, group_order, bn_ctx), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_mod_mul(sk_part2, sk_part2, p1_bn, group_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(BN_mod_mul(sk_part2, sk_part2, sign2->z_, group_order, bn_ctx), !=, 1);

    //calc sk = sk_part1 + sk_part2 = z1 * p2 / (p2 - p1) + z2 * p1 / (p1 - p2)
    BIGNUM* sk_bn;
    CHECK_OPENSSL_ERROR(sk_bn = BN_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_mod_add(sk_bn, sk_part1, sk_part2, group_order, bn_ctx), !=, 1);
    CHECK_OPENSSL_ERROR(sk->sk_sign_ = EC_KEY_new(), ==, NULL);
    CHECK_OPENSSL_ERROR(EC_KEY_set_group(sk->sk_sign_, group), !=, 1);
    CHECK_OPENSSL_ERROR(EC_KEY_set_private_key(sk->sk_sign_, sk_bn), !=, 1);

    //convert secret signing key to char array
    uint8_t* sk_sign_char;
    size_t sk_sign_length;
    int size;
    CHECK_OPENSSL_ERROR(size = BN_num_bytes(sk_bn), <=, 0);
    sk_sign_length = (size_t)size;
    CHECK_OPENSSL_ERROR(sk_sign_char = OPENSSL_malloc(sk_sign_length), ==, NULL);
    CHECK_OPENSSL_ERROR(BN_bn2bin(sk_bn, sk_sign_char), <=, 0);

    //set up hkdf
    EVP_PKEY_CTX* pctx;
    CHECK_OPENSSL_ERROR(pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, NULL), ==, NULL);
    CHECK_OPENSSL_ERROR(EVP_PKEY_derive_init(pctx), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set_hkdf_md(pctx, EVP_sha256()), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set1_hkdf_salt(pctx, HKDF_SALT, strlen(HKDF_SALT)), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_add1_hkdf_info(pctx, HKDF_INFO, strlen(HKDF_INFO)), !=, 1);
    CHECK_OPENSSL_ERROR(EVP_PKEY_CTX_set1_hkdf_key(pctx, sk_sign_char, sk_sign_length), !=, 1);

    int bn_max_length;
    size_t bn_max_length_unsigned;
    CHECK_OPENSSL_ERROR(bn_max_length = BN_num_bytes(group_order), <=, 0);
    bn_max_length_unsigned = (size_t)bn_max_length;
    CHECK_OPENSSL_ERROR(sk->r_i_ = OPENSSL_malloc(pk->n_ * sizeof(BIGNUM*)), ==, NULL);
    CHECK_OPENSSL_ERROR(sk->rho_i_ = OPENSSL_malloc(pk->n_ * sizeof(BIGNUM*)), ==, NULL);

    uint8_t* tmp;
    CHECK_OPENSSL_ERROR(tmp = OPENSSL_malloc(bn_max_length_unsigned), ==, NULL);

    //get y
    for(int i = 0; i < pk->n_; ++i)
    {
        //get r_i
        CHECK_OPENSSL_ERROR(EVP_PKEY_derive(pctx, tmp, &bn_max_length_unsigned), !=, 1);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            tmp[j] ^= pk->y_[i][j];

        //convert r_i to BIGNUM
        CHECK_OPENSSL_ERROR(sk->r_i_[i] = BN_new(), ==, NULL);
        CHECK_OPENSSL_ERROR(BN_bin2bn(tmp, bn_max_length, sk->r_i_[i]), ==, NULL);

        //get rho_i
        CHECK_OPENSSL_ERROR(EVP_PKEY_derive(pctx, tmp, &bn_max_length_unsigned), !=, 1);
        for(int j = 0; j < bn_max_length_unsigned; ++j)
            tmp[j] ^= pk->y_[i + pk->n_][j];

        //convert rho_i to BIGNUM
        CHECK_OPENSSL_ERROR(sk->rho_i_[i] = BN_new(), ==, NULL);
        CHECK_OPENSSL_ERROR(BN_bin2bn(tmp, bn_max_length, sk->rho_i_[i]), ==, NULL);
    }
    sk->n_ = pk->n_;

    //clean up
    OPENSSL_free(p1_char);
    OPENSSL_free(p2_char);
    OPENSSL_free(sk_sign_char);
    OPENSSL_free(tmp);
    BN_free(p1_bn);
    BN_free(p2_bn);
    BN_free(sk_part1);
    BN_free(sk_part2);
    BN_free(sk_bn);
    BN_CTX_free(bn_ctx);
    EVP_PKEY_CTX_free(pctx);

    return SUCCESS;
}

//----------------------------------------------------------------------------------------------------------------------
//helper functions
//----------------------------------------------------------------------------------------------------------------------

void dapsPkFree(DapsPK** pk)
{
    if(*pk == NULL)
        return;

    EC_KEY_free((*pk)->pk_sign_);

    EC_KEY_free((*pk)->pk_enc_);

    if((*pk)->c1_i_ != NULL)
    {
        for (int i = 0; i < (*pk)->n_; ++i)
            EC_POINT_free((*pk)->c1_i_[i]);

        OPENSSL_free((*pk)->c1_i_);
    }

    if((*pk)->c2_i_ != NULL)
    {
        for(int i = 0; i < (*pk)->n_; ++i)
            EC_POINT_free((*pk)->c2_i_[i]);

        OPENSSL_free((*pk)->c2_i_);
    }

    if((*pk)->y_ != NULL)
    {
        for(int i = 0; i < (2 * (*pk)->n_); ++i)
            OPENSSL_free((*pk)->y_[i]);

        OPENSSL_free((*pk)->y_);
    }

    OPENSSL_free(*pk);
    *pk = NULL;
}

void dapsSkFree(DapsSK** sk)
{
    if(*sk == NULL)
        return;

    EC_KEY_free((*sk)->sk_sign_);

    if((*sk)->rho_i_ != NULL)
    {
        for (int i = 0; i < (*sk)->n_; ++i)
            BN_free((*sk)->rho_i_[i]);

        OPENSSL_free((*sk)->rho_i_);
    }

    if((*sk)->r_i_ != NULL)
    {
        for (int i = 0; i < (*sk)->n_; ++i)
            BN_free((*sk)->r_i_[i]);

        OPENSSL_free((*sk)->r_i_);
    }

    OPENSSL_free(*sk);
    *sk = NULL;
}

void dapsMsgFree(DapsMessage** m)
{
    if(*m == NULL)
        return;

    OPENSSL_free((*m)->p_);

    OPENSSL_free(*m);
    *m = NULL;
}

void dapsSignatureFree(DapsSignature** sign)
{
    if(*sign == NULL)
        return;

    OPENSSL_free((*sign)->sigma_);

    EC_POINT_free((*sign)->t1_);

    EC_POINT_free((*sign)->t2_);

    BN_free((*sign)->s_);

    BN_free((*sign)->z_);

    OPENSSL_free(*sign);
    *sign = NULL;
}

DapsPK* dapsPkNew()
{
    DapsPK* pk = OPENSSL_zalloc(sizeof(DapsPK));
    return pk;
}

DapsSK* dapsSkNew()
{
    DapsSK* sk = OPENSSL_zalloc(sizeof(DapsSK));
    return sk;
}

DapsMessage* dapsMsgNew(uint32_t i, const uint8_t* p, size_t p_length)
{
    if(p_length == 0)
        return 0;

    DapsMessage* msg = OPENSSL_malloc(sizeof(DapsMessage));
    if(msg == NULL)
        return NULL;

    msg->p_ = OPENSSL_malloc(p_length);
    if(msg->p_ == NULL)
    {
        dapsMsgFree(&msg);
        return NULL;
    }

    memcpy(msg->p_, p, p_length);

    msg->i_ = i;
    msg->p_length_ = p_length;

    return msg;
}

DapsSignature* dapsSignatureNew(DapsPK* pk)
{
    DapsSignature* sign = OPENSSL_zalloc(sizeof(DapsSignature));
    if(sign == NULL)
        return NULL;

    const EC_GROUP* group = EC_KEY_get0_group(pk->pk_sign_);

    uint32_t sign_size;
    if((sign_size = (uint32_t)ECDSA_size(pk->pk_sign_)) == 0)
    {
        OPENSSL_free(sign);
        return NULL;
    }

    sign->sigma_ = OPENSSL_malloc(sign_size);

    sign->t1_ = EC_POINT_new(group);
    sign->t2_ = EC_POINT_new(group);

    sign->s_ = BN_new();

    sign->z_ = BN_new();

    if(sign->sigma_ == NULL || sign->t1_ == NULL || sign->t2_ == NULL || sign->s_ == NULL || sign->z_ == NULL)
        dapsSignatureFree(&sign);
    else
        sign->sigma_length_ = sign_size;

    return sign;
}