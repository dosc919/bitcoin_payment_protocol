//
// Created by dominik on 11.01.18.
//

#ifndef BITCOIN_APP_CLIENT_H
#define BITCOIN_APP_CLIENT_H

#include "hd_wallet_testnet.h"
#include "state.h"
#include "transaction.h"
#include "defines.h"

class Client
{
private:
    const uint32_t id_;

    HDWalletTestnet wallet_;
    const uint32_t child_id_ = 1; //child of the hierarchical deterministic wallet that should be used
    uint64_t balance_; //balance of the child's address

    DapsSkPtr daps_sk_;
    DapsPkPtr daps_pk_;

    bc::hash_digest deposit_hash_;
    uint64_t deposit_value_;
    uint64_t lock_time_;
    ConstStatePtr latest_state_;

    ConstPubEcKeyPtr provider_pk_;
    bc::wallet::payment_address provider_address_;

    //debug/feedback functions
    void displayNewClient() const;
    void displayNewDeposit(chain::transaction deposit_tx) const;
    void displayNewTransaction(TransactionPtr& transaction) const;

    //------------------------------------------------------------------------------------------------------------------
    // Signs an offline transaction with the client's private DAPS key
    // @input:
    //   transaction...transaction that should be signed
    // @output:
    //   returns the DAPS for the transaction
    //------------------------------------------------------------------------------------------------------------------
    ConstDapsSigPtr signOfflineTransaction(TransactionPtr &transaction);

    //------------------------------------------------------------------------------------------------------------------
    // Creates a signed transaction that transfers Bitcoin from the deposit to the provider
    // @input:
    //   satoshi....Satoshi to transfer to the provider
    // @output:
    //   returns the signed transaction
    //------------------------------------------------------------------------------------------------------------------
    bc::chain::transaction getSignedBcTransaction(uint64_t satoshi);

    //------------------------------------------------------------------------------------------------------------------
    // Fetches a transaction from the network and sets the member balance_ to the value of the spendable output
    // @input:
    //   tx_hash...hash of the transaction that should be fetched
    //   index.....index of the transaction output, which is spendable
    //------------------------------------------------------------------------------------------------------------------
    void setTransactionBalance(hash_digest tx_hash, uint32_t index);

public:
    Client(const uint32_t id, const uint32_t num_addresses, const bc::wallet::word_list& mnemonic);
    ~Client();

    //getter
    ConstDapsPkPtr getDapsPk() const;
    const uint32_t getId() const;
    ConstStatePtr getLatestState() const;
    const bc::short_hash getAddressHash() const;
    const uint64_t getClientBalance(); //queries balance from network

    //setter
    bool setState(ConstStatePtr& new_state);
    void setProviderPk(ConstPubEcKeyPtr provider_pk);
    void setProviderAddress(bc::wallet::payment_address provider_address);
    void setDepositHash(hash_digest tx_hash);
    void setDepositValue(uint64_t value);
    void setLockTime(uint64_t new_lock_time);

    //------------------------------------------------------------------------------------------------------------------
    // Creates a deposit by setting up a pay to script hash (p2sh) transaction and broadcasting it to the Bitcoin
    // (test-)network.
    // @input:
    //   utxo_hash_string.....string containing the hash of a transaction with an unspent transaction output
    //   utxo_index...........index of the unspent transaction output
    //   satoshi_to_spent.....number of Satoshi that will be placed in the deposit
    //   destination_address..address of the beneficiary (provider) of the deposit
    //   lock_time............specifies the time the deposit will be locked in unix time
    // @output:
    //   returns the transaction hash of the deposit transaction or null_hash if an error occured
    //------------------------------------------------------------------------------------------------------------------
    hash_digest createDeposit(const std::string& utxo_hash_string, uint32_t utxo_index, uint64_t satoshi_to_spend,
                              bc::wallet::payment_address destination_address, uint64_t lock_time);

    //------------------------------------------------------------------------------------------------------------------
    // Creates a new offline transaction corresponding to the state in the member variable "latest_state_"
    // @input:
    //   satoshi_to_spent..Satoshi that should be spent in the offline transaction
    //   rnd_nr............random number that was queried from a point of sale (ensures different payloads for the DAPS)
    // @output:
    //   returns the signed offline transaction or nullptr if an error occured
    //------------------------------------------------------------------------------------------------------------------
    ConstTransactionPtr makeOfflineTransaction(const uint64_t satoshi_to_spent,
                                               const std::array<uint8_t, RND_NR_SIZE_BYTES> &rnd_nr);

    //------------------------------------------------------------------------------------------------------------------
    // Transfers all Bitcoin in an expired deposit back to the client's wallet
    //------------------------------------------------------------------------------------------------------------------
    void reclaimDeposit() const;

    //------------------------------------------------------------------------------------------------------------------
    // Creates the redeem script string of the deposit transaction
    // @input:
    //   provider_address...Bitcoin address of the provider
    //   client_address.....Bitcoin address of the client
    //   lock_time..........time, which specifies how long the deposit is locked
    // @output:
    //   returns the script string constructed from the input
    //------------------------------------------------------------------------------------------------------------------
    static std::string createDepositRedeemScript(const short_hash& provider_address,
                                                 const short_hash& client_address, uint64_t lock_time);
};


#endif //BITCOIN_APP_CLIENT_H
