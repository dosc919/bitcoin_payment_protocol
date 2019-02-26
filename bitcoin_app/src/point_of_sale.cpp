//
// Created by dominik on 11.01.18.
//

#include <openssl/sha.h>
#include <openssl/rand.h>
#include <iostream>
#include "point_of_sale.h"
#include "client.h"

PointOfSale::PointOfSale(std::map<uint32_t, ConstDapsPkPtr>& clients, ConstPubEcKeyPtr pk_provider, const uint32_t id,
                         const bc::wallet::payment_address address_provider) :
        daps_pk_by_client_(clients), id_(id), address_provider_(address_provider)
{
    ecdsa_key_ = EcKeyPtr(EC_KEY_new_by_curve_name(CURVE));
    EC_KEY_generate_key(ecdsa_key_.get());

    pk_provider_ = std::move(pk_provider);

    getNewRandomNr();
}

PointOfSale::~PointOfSale() = default;

ConstEcdsaSigPtr PointOfSale::getKeySignature() const
{
    return sign_of_key_;
}

ConstPubEcKeyPtr PointOfSale::getPublicEcKey() const
{
    //extract public signing key
    const EC_POINT* pk_sign = EC_KEY_get0_public_key(ecdsa_key_.get());
    const EC_GROUP* grp = EC_KEY_get0_group(ecdsa_key_.get());

    //set up EC_KEY (pk) with a public signing key only
    PubEcKeyPtr pk = PubEcKeyPtr(EC_KEY_new(), EC_KEY_free);
    EC_KEY_set_group(pk.get(), grp);
    EC_KEY_set_public_key(pk.get(), pk_sign);

    return pk;
}

const uint32_t PointOfSale::getId() const
{
    return id_;
}

std::vector<ConstTransactionPtr> PointOfSale::getTransactions() const
{
    return transactions_;
}

bool PointOfSale::setEcKeySignature(ConstEcdsaSigPtr key_signature)
{
    //get public ecdsa key
    const EC_POINT* pk = EC_KEY_get0_public_key(ecdsa_key_.get());
    const EC_GROUP* grp = EC_KEY_get0_group(ecdsa_key_.get());
    size_t point_size = EC_POINT_point2oct(grp, pk, EC_GROUP_get_point_conversion_form(grp), NULL, 0, NULL);
    auto pk_bytes = new uint8_t[point_size];
    EC_POINT_point2oct(grp, pk, EC_GROUP_get_point_conversion_form(grp), pk_bytes, point_size, NULL);

    //verify if the signature is valid
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(pk_bytes, point_size, md);

    if(ECDSA_do_verify(md, SHA256_DIGEST_LENGTH, key_signature.get(), (EC_KEY*)pk_provider_.get()) != 1)
        return false;

    //set the signature
    sign_of_key_ = std::move(key_signature);
    return true;
}

const std::array<uint8_t, RND_NR_SIZE_BYTES> PointOfSale::getNewRandomNr()
{
    RAND_bytes(&(randomness_[0]), randomness_.size());
    return randomness_;
};

ConstStatePtr PointOfSale::receiveOfflineTransaction(ConstTransactionPtr &tx, ConstStatePtr &state)
{
    if(tx == nullptr || state == nullptr)
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: transaction or state is null" << std::endl;
        return ConstStatePtr(nullptr);
    }

    const TransactionData tx_data = tx->getData();
    const StateData state_data = state->getData();

    ConstDapsPkPtr client_daps_pk = daps_pk_by_client_[state_data.getClientId()];
    if(!checkDapsSignature(tx, client_daps_pk))
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: daps signature of transaction is invalid" << std::endl;
        return ConstStatePtr(nullptr);
    }

    if(!state->checkSignature(pk_provider_))
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: signature of state is invalid" << std::endl;
        return ConstStatePtr(nullptr);
    }

    uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    uint64_t expire_time = state_data.getExpireTime();
    if(now + EXPIRE_TIME_MARGIN >= expire_time)
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: deposit already expired" << std::endl;
        return ConstStatePtr(nullptr);
    }

    if(state_data.getRevisionNr() != tx_data.getRevisionNumber())
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: revision numbers do not match" << std::endl;
        return ConstStatePtr(nullptr);
    }

    //check if randomness matches the last issued randomness and that the randomness is not 0
    auto tx_randomness = tx_data.getRandomNumber();
    if(std::all_of(randomness_.begin(), randomness_.end(), [](uint8_t i){return i == 0;}) ||
       (memcmp(&(tx_randomness[0]), &(randomness_[0]), RND_NR_SIZE_BYTES) != 0))
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: randomness is invalid" << std::endl;
        return ConstStatePtr(nullptr);
    }

    //clear randomness
    memset(&(randomness_[0]), 0, RND_NR_SIZE_BYTES);

    uint64_t satoshi_tx = tx_data.getAmountSpent();
    if(satoshi_tx > state_data.getLimit())
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: satoshis exceed the maximum spendable amount" << std::endl;
        return ConstStatePtr(nullptr);
    }

    const bc::hash_digest transaction_input = tx_data.getTransactionHash();
    const bc::hash_digest deposit_tx_hash = state_data.getDepositTransactionHash();
    if(memcmp(&(transaction_input[0]), &(deposit_tx_hash[0]), deposit_tx_hash.size()) != 0)
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: input transaction hash is not the deposit transaction hash" << std::endl;
        return ConstStatePtr(nullptr);
    }

    const bc::wallet::payment_address tx_output_address = tx_data.getOutputAddress();
    bc::short_hash tx_output_hash = tx_output_address.hash();
    bc::short_hash provider_hash = address_provider_.hash();
    if(memcmp(&(tx_output_hash[0]), &(provider_hash[0]), provider_hash.size()) != 0)
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: output address is not the provider's address" << std::endl;
        return ConstStatePtr(nullptr);
    }

    if(!checkBitcoinTransactionSignature(tx_data.getTransaction(), state_data.getExpireTime()))
    {
        if(VERBOSE && POINT_OF_SALE_VERBOSE)
            std::cout << "\n(PoS) error: the Bitcoin transaction signature is invalid" << std::endl;
        return ConstStatePtr(nullptr);
    }

    transactions_.push_back(tx);

    StatePtr new_state = state->getNextRevision(satoshi_tx);
    ConstEcdsaSigPtr state_signature = signState(new_state);
    new_state->setSignature(state_signature);
    new_state->setSignedPosKey(getPublicEcKey(), getKeySignature());

    if(VERBOSE && POINT_OF_SALE_VERBOSE)
        displayNewState(new_state);

    return new_state;
}

ConstEcdsaSigPtr PointOfSale::signState(StatePtr& state_to_sign) const
{
    std::vector<uint8_t> bytes = state_to_sign->getData().getBytes();
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(&(bytes[0]), bytes.size(), md);

    auto deleteEcdsaSig = [](ECDSA_SIG* sign){ECDSA_SIG_free(sign);};
    ConstEcdsaSigPtr state_signature = ConstEcdsaSigPtr(ECDSA_do_sign(md, SHA256_DIGEST_LENGTH, ecdsa_key_.get()),
                                                        deleteEcdsaSig);

    return state_signature;
}

bool PointOfSale::checkDapsSignature(ConstTransactionPtr& tx, ConstDapsPkPtr& daps_pk) const
{
    std::vector<uint8_t> bytes = tx->getData().getBytes();
    DapsMessage* msg = dapsMsgNew(tx->getData().getRevisionNumber(), &(bytes[0]), bytes.size());

    bool valid = dapsVerify((DapsPK*)(daps_pk.get()), msg, (DapsSignature*)tx->getSignature().get()) == SUCCESS;

    dapsMsgFree(&msg);
    return valid;
}

bool PointOfSale::checkBitcoinTransactionSignature(bc::chain::transaction transaction, uint64_t lock_time) const
{
    //get endorsement and public key from unlocking script
    bc::data_chunk unlocking_script_data = transaction.inputs()[0].script().to_data(false);
    bc::data_chunk unlocking_script_endorsement;
    bc::data_chunk unlocking_script_pk;

    auto script_data_it = unlocking_script_data.begin() + 1;
    unlocking_script_endorsement.assign(script_data_it, script_data_it + unlocking_script_data[0]);
    unlocking_script_pk.assign(script_data_it + unlocking_script_data[0] + 1, unlocking_script_data.end());

    //reconstruct input
    bc::wallet::payment_address address_client = transaction.outputs()[1].address(bc::wallet::payment_address::testnet_p2kh);
    std::string script_string = Client::createDepositRedeemScript(address_provider_.hash(), address_client.hash(), lock_time);

    bc::chain::script cltv_script = bc::chain::script();
    cltv_script.from_string(script_string);

    //check signature of transaction
    uint8_t sig_hash_type;
    bc::der_signature script_signature;
    bc::parse_endorsement(sig_hash_type, script_signature, std::move(unlocking_script_endorsement));

    bc::ec_signature script_ec_signature;
    bc::parse_signature(script_ec_signature, script_signature, false);
    return bc::chain::script().check_signature(script_ec_signature, sig_hash_type, unlocking_script_pk, cltv_script, transaction, 0) == 1;
}

void PointOfSale::displayNewState(StatePtr& state)
{
    std::cout << "\nNew State (point of sale id = " << id_ << "):" << std::endl;
    state->display();
}