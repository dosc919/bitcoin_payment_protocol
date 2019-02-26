//
// Created by dominik on 11.01.18.
//

#include <openssl/sha.h>
#include <bitcoin/client.hpp>
#include "provider.h"
#include "client.h"

Provider::Provider(const bc::wallet::word_list& mnemonic)
{
    ecdsa_key_ = EcKeyPtr(EC_KEY_new_by_curve_name(CURVE));
    EC_KEY_generate_key(ecdsa_key_.get());

    wallet_ = HDWalletTestnet(mnemonic);

    if(VERBOSE && PROVIDER_VERBOSE)
        displayNewProvider();
}

Provider::~Provider() = default;

bool Provider::addClient(const uint32_t id, ConstDapsPkPtr pk)
{
    if(daps_pk_by_client_.find(id) != daps_pk_by_client_.end())
        return false;

    daps_pk_by_client_[id] = std::move(pk);
    return true;
}

ConstPubEcKeyPtr Provider::getPublicEcKey() const
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

ConstStatePtr Provider::getInitialState(hash_digest tx_hash, uint32_t client_id, uint64_t expire_time, const bc::short_hash client_address)
{
    if(!fetchTransaction(tx_hash))
        return ConstStatePtr(nullptr);

    if(!checkDepositTransaction(expire_time, client_address))
        return ConstStatePtr(nullptr);

    lock_time_by_client_[client_id] = expire_time;

    uint64_t spendable_satoshis = fetched_transaction_.outputs()[0].value() / (100 / DEPOSIT_PENALTY_PERCENTAGE);
    StatePtr state = std::make_shared<State>(expire_time, spendable_satoshis, client_id, tx_hash);

    std::vector<uint8_t> bytes = state->getData().getBytes();
    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(&(bytes[0]), bytes.size(), md);

    auto deleteEcdsaSig = [](ECDSA_SIG* sign){ECDSA_SIG_free(sign);};
    ConstEcdsaSigPtr state_signature = ConstEcdsaSigPtr(ECDSA_do_sign(md, SHA256_DIGEST_LENGTH, ecdsa_key_.get()),
                                                        deleteEcdsaSig);
    state->setSignature(state_signature);

    if(VERBOSE && PROVIDER_VERBOSE)
        displayNewState(state);

    return state;
}

const bc::wallet::payment_address Provider::getPaymentAddress() const
{
    return wallet_.childAddress(child_id_);
}

const std::map<uint32_t, ConstDapsPkPtr> Provider::getClientDapsPKs() const
{
    return daps_pk_by_client_;
}

ConstEcdsaSigPtr Provider::signEcKey(ConstPubEcKeyPtr& ecdsa_key) const
{
    const EC_POINT* pk = EC_KEY_get0_public_key(ecdsa_key.get());
    const EC_GROUP* grp = EC_KEY_get0_group(ecdsa_key.get());
    size_t point_size = EC_POINT_point2oct(grp, pk, EC_GROUP_get_point_conversion_form(grp), NULL, 0, NULL);
    auto pk_bytes = new uint8_t[point_size];
    EC_POINT_point2oct(grp, pk, EC_GROUP_get_point_conversion_form(grp), pk_bytes, point_size, NULL);

    uint8_t md[SHA256_DIGEST_LENGTH];
    SHA256(pk_bytes, point_size, md);

    delete pk_bytes;

    auto deleteEcdsaSig = [](ECDSA_SIG* sign){ECDSA_SIG_free(sign);};
    return ConstEcdsaSigPtr(ECDSA_do_sign(md, SHA256_DIGEST_LENGTH, ecdsa_key_.get()), deleteEcdsaSig);
}

void Provider::retrieveBitcoin(std::vector<ConstTransactionPtr> transactions, uint32_t client_id)
{
    if(transactions.empty())
        return;

    std::map<uint32_t, ConstTransactionPtr> tx_by_rev_num;

    uint32_t latest_rev_nr = 0;
    bc::chain::transaction transaction_to_spent;
    for(ConstTransactionPtr& tx : transactions)
    {
        uint32_t rev_nr = tx->getData().getRevisionNumber();
        if(tx_by_rev_num.find(rev_nr) != tx_by_rev_num.end())
        {
            DapsSkPtr daps_sk = extractDapsSecretKey(tx, tx_by_rev_num[rev_nr], daps_pk_by_client_[client_id]);
            bc::wallet::ec_private bc_private_key = extractBitcoinPrivateKey(daps_sk);

            if(VERBOSE && PROVIDER_VERBOSE)
                std::cout << "\nclient private key extracted!" << std::endl;

            bc::chain::transaction transaction = tx->getData().getTransaction();
            transaction_to_spent = getNewSignedTransaction(bc_private_key, transaction, lock_time_by_client_[client_id]);

            wallet_.broadcastTransaction(transaction_to_spent);
            return;
        }
        tx_by_rev_num[rev_nr] = tx;

        if(rev_nr > latest_rev_nr)
            latest_rev_nr = rev_nr;
    }

    transaction_to_spent = tx_by_rev_num[latest_rev_nr]->getData().getTransaction();
    addProviderSignature(transaction_to_spent, lock_time_by_client_[client_id]);

    wallet_.broadcastTransaction(transaction_to_spent);
}

DapsSkPtr Provider::extractDapsSecretKey(ConstTransactionPtr& tx1, ConstTransactionPtr& tx2, ConstDapsPkPtr& daps_pk)
{
    TransactionData tx1_data = tx1->getData();
    TransactionData tx2_data = tx2->getData();

    std::vector<uint8_t> tx1_bytes = tx1_data.getBytes();
    std::vector<uint8_t> tx2_bytes = tx2_data.getBytes();

    DapsMessage* msg1 = dapsMsgNew(tx1_data.getRevisionNumber(), &(tx1_bytes[0]), tx1_bytes.size());
    DapsMessage* msg2 = dapsMsgNew(tx2_data.getRevisionNumber(), &(tx2_bytes[0]), tx2_bytes.size());

    DapsSkPtr sk_extracted = DapsSkPtr(dapsSkNew());
    dapsExtr(sk_extracted.get(), (DapsPK*)daps_pk.get(), msg1, msg2,
             (DapsSignature*)tx1->getSignature().get(), (DapsSignature*)tx2->getSignature().get());

    dapsMsgFree(&msg1);
    dapsMsgFree(&msg2);

    return sk_extracted;
}

bc::wallet::ec_private Provider::extractBitcoinPrivateKey(DapsSkPtr& daps_secret_key)
{
    const EC_KEY* ecdsa_sk = daps_secret_key->sk_sign_;
    const BIGNUM* ecdsa_sk_bn = EC_KEY_get0_private_key(ecdsa_sk);
    ec_secret sk_bytes;
    BN_bn2bin(ecdsa_sk_bn, &(sk_bytes[0]));

    return  wallet::ec_private(sk_bytes, wallet::payment_address::testnet_p2kh, false);
}

bc::chain::transaction Provider::getNewSignedTransaction(bc::wallet::ec_private& private_key,
                                                         bc::chain::transaction& tx, uint64_t lock_time)
{
    //construct input
    bc::chain::transaction new_tx = bc::chain::transaction();

    bc::chain::input input1 = bc::chain::input();
    input1.set_previous_output(tx.previous_outputs()[0]);
    input1.set_sequence(0xffffffff);
    new_tx.inputs().push_back(input1);

    //construct output
    uint64_t satoshi = 0;
    for(const auto& out : tx.outputs())
        satoshi += out.value();

    bc::chain::script output = bc::chain::script(bc::chain::script().to_pay_key_hash_pattern(wallet_.childAddress(1).hash()));
    bc::chain::output output1(satoshi, output);
    new_tx.outputs().push_back(output1);

    //sign transaction
    wallet::ec_public public_key = wallet::ec_public(private_key.to_public().point());
    std::string script_string = Client::createDepositRedeemScript(wallet_.childAddress(child_id_).hash(),
                                                                  public_key.to_payment_address().hash(), lock_time);

    bc::chain::script cltv_script = bc::chain::script();
    cltv_script.from_string(script_string);

    endorsement sig_provider;
    bc::chain::script().create_endorsement(sig_provider, wallet_.childPrivateKey(child_id_).secret(), cltv_script, new_tx, 0u, bc::machine::all);

    endorsement sig_client;
    bc::chain::script().create_endorsement(sig_client, private_key.secret(), cltv_script, new_tx, 0u, bc::machine::all);

    //build unlocking script
    machine::operation::list sig_script;
    sig_script.push_back(machine::operation(sig_client));
    sig_script.push_back(machine::operation(to_chunk(private_key.to_public().point())));
    sig_script.push_back(machine::operation(sig_provider));
    sig_script.push_back(machine::operation(to_chunk(wallet_.childPublicKey(child_id_).point())));
    sig_script.push_back(machine::operation(bc::machine::opcode(81)));
    sig_script.push_back(machine::operation(cltv_script.to_data(false)));
    bc::chain::script unlocking_script(sig_script);

    new_tx.inputs()[0].set_script(unlocking_script);

    return new_tx;
}

void Provider::addProviderSignature(bc::chain::transaction& transaction, uint64_t lock_time)
{
    //build redeem script
    short_hash client_address = transaction.outputs()[1].address().hash();
    std::string script_string = Client::createDepositRedeemScript(wallet_.childAddress(child_id_).hash(), client_address, lock_time);

    bc::chain::script cltv_script = bc::chain::script();
    cltv_script.from_string(script_string);

    //sign transaction
    endorsement sig_provider;
    bc::chain::script().create_endorsement(sig_provider, wallet_.childPrivateKey(child_id_).secret(), cltv_script, transaction, 0u, bc::machine::all);

    //build unlocking script
    machine::operation::list sig_script = transaction.inputs()[0].script().operations();
    sig_script.push_back(machine::operation(sig_provider));
    sig_script.push_back(machine::operation(to_chunk(wallet_.childPublicKey(child_id_).point())));
    sig_script.push_back(machine::operation(bc::machine::opcode(81)));
    sig_script.push_back(machine::operation(cltv_script.to_data(false)));
    bc::chain::script unlocking_script(sig_script);

    transaction.inputs()[0].set_script(unlocking_script);
}

bool Provider::fetchTransaction(hash_digest tx_hash)
{
    client::connection_type connection = {};
    connection.retries = 3;
    connection.timeout_seconds = 8;
    connection.server = config::endpoint(LIBBITCOIN_TESTNET_SERVER);

    client::obelisk_client client(connection);

    bool status = true;

    const auto on_done = [this](const chain::transaction& tx){
        this->fetched_transaction_ = tx;
    };

    static const auto on_error = [&status](const code& ec){
        std::cout << "Error Code: " << ec.message() << std::endl;
        status = false;
    };

    if(!client.connect(connection))
    {
        std::cout << "Fail" << std::endl;
        return false;
    }
    else
    {
        std::cout << "\nConnection Succeeded" << std::endl;
    }

    client.blockchain_fetch_transaction(on_error, on_done, tx_hash);
    client.wait();

    return status;
}

bool Provider::checkDepositTransaction(uint64_t expire_time, short_hash client_address)
{
    std::string script_string = Client::createDepositRedeemScript(wallet_.childAddress(child_id_).hash(), client_address, expire_time);

    bc::chain::script cltv_script = bc::chain::script();
    cltv_script.from_string(script_string);

    bc::wallet::payment_address cltv_address(cltv_script);
    bc::chain::script output_script(bc::chain::script().to_pay_script_hash_pattern(cltv_address.hash()));

    std::string output_script_string = output_script.to_string(0);

    return output_script_string == fetched_transaction_.outputs()[0].script().to_string(0);
}

void Provider::displayNewState(StatePtr& state) const
{
    std::cout << "\nNew initial state (provider):" << std::endl;
    state->display();
}

void Provider::displayNewProvider() const
{
    std::cout << "\nNew Provider:" << std::endl;
    std::cout << "Mnemonic:" << std::endl;
    wallet_.displayMnemonic();
    wallet_.displayAddress(child_id_);
}