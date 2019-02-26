//
// Created by dominik on 11.01.18.
//

#ifndef BITCOIN_APP_PROVIDER_H
#define BITCOIN_APP_PROVIDER_H

#include <map>
#include "hd_wallet_testnet.h"
#include "point_of_sale.h"
#include "state.h"

#define DEPOSIT_PENALTY_PERCENTAGE 50

class Provider
{
private:
    HDWalletTestnet wallet_;
    const uint32_t child_id_ = 1; //child of the hierarchical deterministic wallet that should be used

    EcKeyPtr ecdsa_key_;

    std::map<uint32_t, ConstDapsPkPtr> daps_pk_by_client_;
    std::map<uint32_t, uint64_t> lock_time_by_client_;

    bc::chain::transaction fetched_transaction_;

    //debug/feedback functions
    void displayNewState(StatePtr& state) const;
    void displayNewProvider() const;

    //------------------------------------------------------------------------------------------------------------------
    // adds the signature of the provider to a Bitcoin transaction, so that it can be spent
    // @input:
    //   transaction...transaction, to which the signature should be added
    //   lock_time.....unix time until which the deposit is locked (necessary to build the unlocking script)
    //------------------------------------------------------------------------------------------------------------------
    void addProviderSignature(bc::chain::transaction& transaction, uint64_t lock_time);

public:
    explicit Provider(const bc::wallet::word_list& mnemonic);

    ~Provider();

    //getter
    ConstPubEcKeyPtr getPublicEcKey() const;
    const bc::wallet::payment_address getPaymentAddress() const;
    const std::map<uint32_t, ConstDapsPkPtr> getClientDapsPKs() const;

    //------------------------------------------------------------------------------------------------------------------
    // Verifies the deposit transaction and returns an initial state, which is signed with the providers private
    // ecdsa key
    // @input:
    //   tx_hash.........transaction hash of the deposit transaction
    //   client_id.......id of the client, who set up the deposit
    //   expire_time.....unix time at which the deposit expires
    //   client_address..address of the clients Bitcoin wallet
    // @output:
    //   returns a signed initial state or a null pointer if an error occured
    //------------------------------------------------------------------------------------------------------------------
    ConstStatePtr getInitialState(hash_digest tx_hash, uint32_t client_id, uint64_t expire_time, const short_hash client_address);

    //------------------------------------------------------------------------------------------------------------------
    // adds a client with the client's public DAPS key
    // @input:
    //   id...id of the client
    //   pk...public DAPS key of the client
    // @output:
    //   returns true if the client was added and false if an error occured or if the client was already added
    //------------------------------------------------------------------------------------------------------------------
    bool addClient(const uint32_t id, ConstDapsPkPtr pk);

    //------------------------------------------------------------------------------------------------------------------
    // signs the public ecdsa key of a point of sale with the provider's private ecdsa key
    // @input:
    //   ecdsa_key...ecdsa key of the point of sale, which will be signed
    // @output:
    //   returns the signature of the key
    //------------------------------------------------------------------------------------------------------------------
    ConstEcdsaSigPtr signEcKey(ConstPubEcKeyPtr& ecdsa_key) const;

    //------------------------------------------------------------------------------------------------------------------
    // checks the provided transactions for double spending and broadcasts the most recent transaction to the Bitcoin
    // network. If double spending is detected, the client's private key is extracted and a new transaction is created,
    // which sends all Bitcoin in the client's deposit to the provider.
    // @input:
    //   transactions...transactions that will be checked
    //   client_id......id of the client, who created the transactions
    //------------------------------------------------------------------------------------------------------------------
    void retrieveBitcoin(std::vector<ConstTransactionPtr> transactions, uint32_t client_id);

    //------------------------------------------------------------------------------------------------------------------
    // extracts the private DAPS key of two signed and colliding transactions
    // @input:
    //   tx1......colliding
    //   tx2......transactions
    //   daps_pk..public DAPS key, which can verify the transactions
    // @output:
    //   extracted private DAPS key
    //------------------------------------------------------------------------------------------------------------------
    DapsSkPtr extractDapsSecretKey(ConstTransactionPtr& tx1, ConstTransactionPtr& tx2, ConstDapsPkPtr& daps_pk);

    //------------------------------------------------------------------------------------------------------------------
    // extracts the ecdsa key from the DAPS key and then creates a Bitcoin private key from the ecdsa key
    // @inputs:
    //   daps_secret_key...DAPS key from which the ecdsa key should be extracted
    // @outputs:
    //   returns a private Bitcoin key
    //------------------------------------------------------------------------------------------------------------------
    bc::wallet::ec_private extractBitcoinPrivateKey(DapsSkPtr& daps_secret_key);

    //------------------------------------------------------------------------------------------------------------------
    // creates a new signed transaction, which transfers all Bitcoin in the client's deposit to the wallet of the
    // provider
    // @input:
    //   private_key..private Bitcoin key of the client
    //   tx...........a Bitcoin transaction of the client, to determine the amount of Bitcoin in the deposit
    //   lock_time.....unix time until which the deposit is locked
    // @output:
    //   returns a signed transaction
    //------------------------------------------------------------------------------------------------------------------
    bc::chain::transaction getNewSignedTransaction(bc::wallet::ec_private& private_key, bc::chain::transaction& tx,
                                                                                                    uint64_t lock_time);

    //------------------------------------------------------------------------------------------------------------------
    // fetches a transaction from the Bitcoin network and stores it in the "fetched_transaction_" member
    // @input:
    //   tx_hash...hash of the transaction, which should be fetched
    // @output:
    //   returns true if the transaction was fetched successfully and false otherwise
    //------------------------------------------------------------------------------------------------------------------
    bool fetchTransaction(hash_digest tx_hash);

    //------------------------------------------------------------------------------------------------------------------
    // Reconstructs the locking script for the deposit and checks if it matches with the transaction previously fetched
    // from the network (fetched_transaction_)
    // @input:
    //   expire_time.....unix time at which the deposit expires
    //   client_address..wallet address of the client
    // @output:
    //   returns true if the deposit transaction is valid and false otherwise
    //------------------------------------------------------------------------------------------------------------------
    bool checkDepositTransaction(uint64_t expire_time, short_hash client_address);
};


#endif //BITCOIN_APP_PROVIDER_H
