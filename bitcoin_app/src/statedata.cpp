//
// Created by dominik on 11.01.18.
//

#include "statedata.h"

StateData::StateData(uint64_t expire_time, uint64_t limit, uint32_t client_id, bc::hash_digest tx_hash) :
        expire_time_(expire_time), limit_(limit), client_id_(client_id), deposit_tx_hash_(tx_hash),
        spent_(0), revision_nr_(0)
{
}

StateData::~StateData() = default;

StateData::StateData(const StateData* state, uint64_t spent) :
        expire_time_(state->expire_time_), limit_(state->limit_), client_id_(state->client_id_),
        deposit_tx_hash_(state->deposit_tx_hash_), spent_(spent), revision_nr_((state->revision_nr_) + 1)
{
}

StateData StateData::getNextRev(uint64_t spent) const
{
    return StateData(this, spent);
}

const std::vector<uint8_t> StateData::getBytes() const
{
    std::vector<uint8_t> bytes = std::vector<uint8_t>(sizeof(StateData));
    memcpy(&(bytes[0]), this, sizeof(StateData));
    return bytes;
}

const bc::hash_digest StateData::getDepositTransactionHash() const
{
    return deposit_tx_hash_;
}

const uint64_t StateData::getExpireTime() const
{
    return expire_time_;
}

const uint64_t StateData::getLimit() const
{
    return limit_;
}

const uint64_t StateData::getSpent() const
{
    return spent_;
}

const uint32_t StateData::getRevisionNr() const
{
    return revision_nr_;
}

const uint32_t StateData::getClientId() const
{
    return client_id_;
}
