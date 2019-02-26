//
// Created by dominik on 14.01.18.
//

#include <openssl/sha.h>
#include <iostream>
#include "state.h"

State::State(uint64_t expire_time, uint64_t limit, uint32_t client_id, bc::hash_digest tx_hash) :
        data_(expire_time, limit, client_id, tx_hash)
{
}

State::State(StateData data) : data_(data)
{
}

State::~State() = default;

const StateData State::getData() const
{
    return data_;
}

ConstEcdsaSigPtr State::getSignature() const
{
    return sign_;
}

void State::setSignature(ConstEcdsaSigPtr state_signature)
{
    sign_ = std::move(state_signature);
}

void State::setSignedPosKey(ConstPubEcKeyPtr pos_key, ConstEcdsaSigPtr pos_key_signature)
{
    pos_pub_key_ = std::move(pos_key);
    pos_pub_key_sign_ = std::move(pos_key_signature);
    has_pos_sign_ = true;
}

bool State::checkSignature(ConstPubEcKeyPtr& ecdsa_pk) const
{
    std::vector<uint8_t> bytes = data_.getBytes();
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(&(bytes[0]), bytes.size(), md);

    if(has_pos_sign_)
    {
        //verify the signature of the data
        if(ECDSA_do_verify(md, SHA256_DIGEST_LENGTH, sign_.get(), (EC_KEY*)pos_pub_key_.get()) != 1)
            return false;

        const EC_POINT* pk = EC_KEY_get0_public_key(pos_pub_key_.get());
        const EC_GROUP* grp = EC_KEY_get0_group(pos_pub_key_.get());
        size_t point_size = EC_POINT_point2oct(grp, pk, EC_GROUP_get_point_conversion_form(grp), NULL, 0, NULL);
        std::unique_ptr<uint8_t> pk_bytes(new uint8_t[point_size]);
        EC_POINT_point2oct(grp, pk, EC_GROUP_get_point_conversion_form(grp), pk_bytes.get(), point_size, NULL);

        //verify the signature of the point of sale's public key
        uint8_t pk_md[SHA256_DIGEST_LENGTH];
        SHA256(pk_bytes.get(), point_size, pk_md);
        return ECDSA_do_verify(pk_md, SHA256_DIGEST_LENGTH, pos_pub_key_sign_.get(), (EC_KEY*)ecdsa_pk.get()) == 1;
    }
    else
    {
        //verify the signature of the data
        return ECDSA_do_verify(md, SHA256_DIGEST_LENGTH, sign_.get(), (EC_KEY*)ecdsa_pk.get()) == 1;
    }
}

StatePtr State::getNextRevision(uint64_t satoshi_spent) const
{
    StateData data = data_.getNextRev(satoshi_spent);
    return std::make_shared<State>(data);
}

bool State::isUpdateTo(ConstStatePtr& old_state) const
{
    StateData old_data = old_state->getData();

    if(old_data.getRevisionNr() >= data_.getRevisionNr())
        return false;

    if(old_data.getLimit() != data_.getLimit())
        return false;

    if(old_data.getSpent() >= data_.getSpent())
        return false;

    if(old_data.getClientId() != data_.getClientId())
        return false;

    if(old_data.getExpireTime() != data_.getExpireTime())
        return false;

    return true;
}

void State::display() const
{
    std::cout << "expire time   : " << data_.getExpireTime() << std::endl;
    std::cout << "satoshis limit: " << data_.getLimit() << std::endl;
    std::cout << "satoshis spent: " << data_.getSpent() << std::endl;
    std::cout << "revision nr.  : " << data_.getRevisionNr() << std::endl;
    std::cout << "client id     : " << data_.getClientId() << std::endl;
    std::cout << "deposit transaction hash:\n" << bc::encode_hash(data_.getDepositTransactionHash()) << std::endl;
}