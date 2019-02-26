//
// Created by dominik on 11.01.18.
//

#ifndef BITCOIN_APP_STATE_DATA_H
#define BITCOIN_APP_STATE_DATA_H

#include <bitcoin/bitcoin.hpp>

class StateData
{
private:
    bc::hash_digest deposit_tx_hash_;
    uint64_t expire_time_;
    uint64_t limit_;
    uint64_t spent_;
    uint32_t revision_nr_;
    uint32_t client_id_;

    StateData(const StateData* state, uint64_t spent);

public:
    StateData(uint64_t expire_time, uint64_t limit, uint32_t client_id, bc::hash_digest tx_hash);
    ~StateData();

    //------------------------------------------------------------------------------------------------------------------
    // Creates an updated version of the state data with the next revision number
    // @input:
    //   satoshi_spent...new amount of satoshi that are spent
    // @output:
    //   returns the updated state data
    //------------------------------------------------------------------------------------------------------------------
    StateData getNextRev(uint64_t spent) const;

    //getter
    const std::vector<uint8_t> getBytes() const;
    const bc::hash_digest getDepositTransactionHash() const;
    const uint64_t getExpireTime() const;
    const uint64_t getLimit() const;
    const uint64_t getSpent() const;
    const uint32_t getRevisionNr() const;
    const uint32_t getClientId() const;
};


#endif //BITCOIN_APP_STATE_DATA_H
