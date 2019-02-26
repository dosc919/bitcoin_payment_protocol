//
// Created by dominik on 03.10.17.
//

#include "gtest/gtest.h"

extern "C"
{
#include "data_structures.h"
#include "const_and_error.h"
#include "daps.h"
#include <openssl/sha.h>
#include <openssl/rand.h>
}

#define NUM_ADDRESSES (10)
#define ADDRESS_TO_SIGN (5)

static const uint8_t P_TEST[] = {0x30, 0x46, 0x2, 0x21, 0x0, 0xbf, 0xbe, 0x66, 0xe6, 0x81, 0xd3, 0xaf, 0x5d, 0x1e, 0x23,
                                 0x26, 0x44, 0x1a, 0x9, 0x3a, 0x5e, 0x40, 0xb4, 0x58, 0x2d, 0x3f, 0xd4, 0xe6, 0xc3, 0x0,
                                 0x79, 0x6d, 0x8e, 0xb8, 0xab, 0xdc, 0x49};


class SignatureTest : public ::testing::Test
{
protected:
    virtual void SetUp()
    {
        pk_ = dapsPkNew();
        sk_ = dapsSkNew();

        ASSERT_TRUE(pk_ != NULL);
        ASSERT_TRUE(sk_ != NULL);

        n_ = NUM_ADDRESSES;

        ASSERT_EQ(error_ = dapsKeyGen(sk_, pk_, n_), SUCCESS) << getErrorString(error_);

        sign_ = dapsSignatureNew(pk_);
        ASSERT_TRUE(sign_ != NULL);
    }

    virtual void TearDown()
    {
        dapsSkFree(&sk_);
        dapsPkFree(&pk_);
        dapsMsgFree(&msg_);
        dapsSignatureFree(&sign_);
    }

    DapsPK* pk_;
    DapsSK* sk_;
    DapsSignature* sign_;
    DapsMessage* msg_;
    ErrorCodes error_;
    uint32_t n_;
};


TEST_F(SignatureTest, test_sign_creation)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_TRUE(sign_ != NULL);
    ASSERT_TRUE(sign_->sigma_ != NULL);
    ASSERT_TRUE(sign_->sigma_length_ == 72);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    //verify ecdsa signature
    SHA256_CTX sha_ctx;
    uint8_t * md = (uint8_t*)OPENSSL_malloc(SHA256_DIGEST_LENGTH);
    ASSERT_TRUE(md != NULL);
    SHA256_Init(&sha_ctx);
    SHA256_Update(&sha_ctx, msg_->p_, msg_->p_length_);
    SHA256_Update(&sha_ctx, &(msg_->i_), sizeof(msg_->i_));
    SHA256_Final(md, &sha_ctx);
    EXPECT_EQ(ECDSA_verify(0, md, SHA256_DIGEST_LENGTH, sign_->sigma_, sign_->sigma_length_, pk_->pk_sign_), 1);

    OPENSSL_free(md);
}

TEST_F(SignatureTest, test_sign_verify)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), SUCCESS) << getErrorString(error_);
}

TEST_F(SignatureTest, test_sign_verify_payload_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    msg_->p_[0] ^= 1;

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);
}

TEST_F(SignatureTest, test_sign_verify_address_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    msg_->i_ ^= 1;

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);
}

TEST_F(SignatureTest, test_sign_verify_pk_sign_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_sign_);
    EC_POINT* pk_new = EC_POINT_new(group);
    BIGNUM* num = BN_new();
    BN_rand_range(num, EC_GROUP_get0_order(group));
    EC_POINT_mul(group, pk_new, num, EC_KEY_get0_public_key(pk_->pk_sign_), num, NULL);
    EC_KEY_set_public_key(pk_->pk_sign_, pk_new);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);

    EC_POINT_free(pk_new);
    BN_free(num);
}

TEST_F(SignatureTest, test_sign_verify_pk_enc_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    EC_POINT* pk_new = EC_POINT_new(group);
    BIGNUM* num = BN_new();
    BN_rand_range(num, EC_GROUP_get0_order(group));
    EC_POINT_mul(group, pk_new, num, EC_KEY_get0_public_key(pk_->pk_enc_), num, NULL);
    EC_KEY_set_public_key(pk_->pk_enc_, pk_new);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);

    EC_POINT_free(pk_new);
    BN_free(num);
}

TEST_F(SignatureTest, test_sign_verify_c1_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BIGNUM* num = BN_new();
    BN_rand_range(num, EC_GROUP_get0_order(group));
    EC_POINT_mul(group, pk_->c1_i_[msg_->i_], num, pk_->c1_i_[msg_->i_], num, NULL);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);

    BN_free(num);
}

TEST_F(SignatureTest, test_sign_verify_c2_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BIGNUM* num = BN_new();
    BN_rand_range(num, EC_GROUP_get0_order(group));
    EC_POINT_mul(group, pk_->c2_i_[msg_->i_], num, pk_->c2_i_[msg_->i_], num, NULL);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);

    BN_free(num);
}

TEST_F(SignatureTest, test_sign_verify_sign_s_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BN_rand_range(sign_->s_, EC_GROUP_get0_order(group));

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);
}

TEST_F(SignatureTest, test_sign_verify_sign_t1_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BIGNUM* num = BN_new();
    BN_rand_range(num, EC_GROUP_get0_order(group));
    EC_POINT_mul(group, sign_->t1_, num, NULL, NULL, NULL);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);

    BN_free(num);
}

TEST_F(SignatureTest, test_sign_verify_sign_t2_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BIGNUM* num = BN_new();
    BN_rand_range(num, EC_GROUP_get0_order(group));
    EC_POINT_mul(group, sign_->t2_, num, NULL, NULL, NULL);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);

    BN_free(num);
}

TEST_F(SignatureTest, test_sign_verify_sign_z_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    const EC_GROUP* group = EC_KEY_get0_group(pk_->pk_enc_);
    BN_rand_range(sign_->z_, EC_GROUP_get0_order(group));

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);
}

TEST_F(SignatureTest, test_sign_verify_sign_sigma_different)
{
    ASSERT_TRUE(sk_ != NULL);
    ASSERT_TRUE(pk_->pk_sign_ != NULL);

    ASSERT_TRUE(pk_ != NULL);
    ASSERT_TRUE(sk_->sk_sign_ != NULL);

    msg_ = dapsMsgNew(ADDRESS_TO_SIGN, P_TEST, sizeof(P_TEST));
    ASSERT_LT(msg_->i_, n_);
    ASSERT_TRUE(msg_->p_ != NULL);

    ASSERT_EQ(error_ = dapsSign(sign_, sk_, pk_, msg_), SUCCESS) << getErrorString(error_);

    RAND_bytes(sign_->sigma_, sign_->sigma_length_);

    EXPECT_EQ(error_ = dapsVerify(pk_, msg_, sign_), VERIFY_SIGNATURE_INVALID) << getErrorString(error_);
}