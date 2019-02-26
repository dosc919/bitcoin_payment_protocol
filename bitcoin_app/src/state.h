//
// Created by dominik on 14.01.18.
//

#ifndef BITCOIN_APP_STATE_H
#define BITCOIN_APP_STATE_H

#include "statedata.h"
#include "defines.h"

class State;
typedef std::shared_ptr<State> StatePtr;
typedef std::shared_ptr<const State> ConstStatePtr;

class State
{
private:
    StateData data_;
    ConstEcdsaSigPtr sign_;

    ConstPubEcKeyPtr pos_pub_key_;
    ConstEcdsaSigPtr pos_pub_key_sign_;
    bool has_pos_sign_ = false;

public:
    State(uint64_t expire_time, uint64_t limit, uint32_t client_id, bc::hash_digest tx_hash);
    explicit State(StateData data);
    ~State();

    //getter
    const StateData getData() const;
    ConstEcdsaSigPtr getSignature() const;

    //setter
    void setSignature(ConstEcdsaSigPtr state_signature);
    void setSignedPosKey(ConstPubEcKeyPtr pos_key, ConstEcdsaSigPtr pos_key_signature);

    //------------------------------------------------------------------------------------------------------------------
    // verifies the signature of the state and if it was signed by a point of sale, the signature of the point of sale's
    // public key as well
    // @input:
    //   ecdsa_pk...public key, which is used to verify the signature
    // @output:
    //   returns true if the signature is valid and false otherwise
    //------------------------------------------------------------------------------------------------------------------
    bool checkSignature(ConstPubEcKeyPtr& ecdsa_pk) const;

    //------------------------------------------------------------------------------------------------------------------
    // Creates an updated version of the state with the next revision number
    // @input:
    //   satoshi_spent...new amount of satoshi that are spent
    // @output:
    //   returns the updated state
    //------------------------------------------------------------------------------------------------------------------
    StatePtr getNextRevision(uint64_t satoshi_spent) const;

    //------------------------------------------------------------------------------------------------------------------
    // Checks if this state is an update to the provided state
    // @input:
    //   old_state...potential previous state of this state
    // @output:
    //   returns true if this state is an update to the "old_state" and false otherwise
    //------------------------------------------------------------------------------------------------------------------
    bool isUpdateTo(ConstStatePtr& old_state) const;

    //------------------------------------------------------------------------------------------------------------------
    // prints the content of data_ to stdout
    //------------------------------------------------------------------------------------------------------------------
    void display() const;
};


#endif //BITCOIN_APP_STATE_H
