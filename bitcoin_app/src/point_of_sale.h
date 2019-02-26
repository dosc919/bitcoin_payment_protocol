//
// Created by dominik on 11.01.18.
//

#ifndef BITCOIN_APP_POINTOFSALE_H
#define BITCOIN_APP_POINTOFSALE_H

#include <map>
#include <bitcoin/bitcoin/wallet/payment_address.hpp>
#include "defines.h"
#include "transaction.h"
#include "state.h"

class PointOfSale;
typedef std::shared_ptr<PointOfSale> PoSPtr;
typedef std::shared_ptr<const PointOfSale> ConstPoSPtr;

//10 min. margin for transaction broadcasting +
//240 min. margin as safety measure against pre-mining attacks
#define EXPIRE_TIME_MARGIN ((10 + 240) * 60)

class PointOfSale
{
private:
    const uint32_t id_;
    EcKeyPtr ecdsa_key_;
    ConstEcdsaSigPtr sign_of_key_;

    ConstPubEcKeyPtr pk_provider_;
    const bc::wallet::payment_address address_provider_;

    std::map<uint32_t, ConstDapsPkPtr> daps_pk_by_client_;
    std::vector<ConstTransactionPtr> transactions_;
    std::array<uint8_t, RND_NR_SIZE_BYTES> randomness_; //is cleared after each use

    //debug/feedback function
    void displayNewState(StatePtr& state);

    //------------------------------------------------------------------------------------------------------------------
    // signs a state with the point of sale's private ecdsa key
    // @input:
    //   state_to_sign...state that will be signed
    // @return:
    //   returns the signature of the state
    //------------------------------------------------------------------------------------------------------------------
    ConstEcdsaSigPtr signState(StatePtr& state_to_sign) const;

public:
    PointOfSale(std::map<uint32_t, ConstDapsPkPtr>& clients, ConstPubEcKeyPtr pk_provider, uint32_t id,
                const bc::wallet::payment_address address_provider);
    ~PointOfSale();

    //getter
    ConstEcdsaSigPtr getKeySignature() const;
    ConstPubEcKeyPtr getPublicEcKey() const;
    const uint32_t getId() const;
    std::vector<ConstTransactionPtr> getTransactions() const;

    //generates a new random number in member "randomness_" and returns it
    const std::array<uint8_t, RND_NR_SIZE_BYTES> getNewRandomNr();

    //setter
    bool setEcKeySignature(ConstEcdsaSigPtr key_signature);

    //------------------------------------------------------------------------------------------------------------------
    // Takes a transaction and a corresponding state as input. Both are checked and if everything is valid the
    // transaction is stored and an updated state is returned.
    // @input:
    //   tx.....transaction for offline payment
    //   state..state, which matches the transaction
    // @output:
    //   returns an update to the input state or a null pointer on error
    //------------------------------------------------------------------------------------------------------------------
    ConstStatePtr receiveOfflineTransaction(ConstTransactionPtr &tx, ConstStatePtr &state);

    //------------------------------------------------------------------------------------------------------------------
    // Verifies if the DAPS of the transaction tx is valid
    // @input:
    //   tx........transaction for which the DAPS should be verified
    //   daps_pk...public DAPS key of the client, who signed the transaction
    // @output:
    //   returns true if the signature is valid and false otherwise
    //------------------------------------------------------------------------------------------------------------------
    bool checkDapsSignature(ConstTransactionPtr& tx, ConstDapsPkPtr& daps_pk) const;

    //------------------------------------------------------------------------------------------------------------------
    // Verifies if the signature of the Bitcoin transaction is valid
    // @input:
    //   transaction...Bitcoin transaction for which the signature should be verified
    //   lock_time.....time until the deposit of the client is locked (necessary to build the unlocking script)
    // @output:
    //   returns true if the signature is valid and false otherwise
    //------------------------------------------------------------------------------------------------------------------
    bool checkBitcoinTransactionSignature(bc::chain::transaction transaction, uint64_t lock_time) const;
};


#endif //BITCOIN_APP_POINTOFSALE_H
