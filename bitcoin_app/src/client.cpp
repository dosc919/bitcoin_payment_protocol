//
// Created by dominik on 11.01.18.
//

#include "client.h"
#include <bitcoin/client.hpp>

Client::Client(const uint32_t id, const uint32_t num_addresses, const bc::wallet::word_list& mnemonic) : id_(id)
{
    auto deleteDapsPk = [](DapsPK* pk){dapsPkFree(&pk);};
    daps_pk_ = DapsPkPtr(dapsPkNew(), deleteDapsPk);
    daps_sk_ = DapsSkPtr(dapsSkNew());
    wallet_ = HDWalletTestnet(mnemonic);

    const ec_secret raw_private_key = wallet_.childPrivateKey(1).secret();

    dapsKeyGenECDSAExternal(daps_sk_.get(), daps_pk_.get(), num_addresses, &(raw_private_key[0]));

    if(VERBOSE && CLIENT_VERBOSE)
        displayNewClient();
}

Client::~Client() = default;

ConstDapsPkPtr Client::getDapsPk() const
{
    return daps_pk_;
}

const uint32_t Client::getId() const
{
    return id_;
}

ConstStatePtr Client::getLatestState() const
{
    return latest_state_;
}

const bc::short_hash Client::getAddressHash() const
{
    return wallet_.childAddress(child_id_).hash();
}

const uint64_t Client::getClientBalance()
{
    client::connection_type connection = {};
    connection.retries = 3;
    connection.timeout_seconds = 8;
    connection.server = config::endpoint(LIBBITCOIN_TESTNET_SERVER);

    client::obelisk_client client(connection);

    uint64_t account_balance = 0;

    const auto on_done = [&account_balance](const chain::history::list& rows){

        uint64_t balance = 0;
        for(const auto& row : rows)
        {
            if(row.spend.hash() == null_hash)
                balance += row.value;
        }
        account_balance = balance;
        std::cout << "\nclient balance: " << balance << " Satoshi" << std::endl;
    };

    static const auto on_error = [](const code& ec){
        std::cout << "\nerror code: " << ec.message() << std::endl;
    };

    if(!client.connect(connection))
    {
        std::cout << "\nconnection failed" << std::endl;
    }
    else
    {
        if(VERBOSE && NETWORK_IO_VERBOSE)
            std::cout << "\nconnection succeeded" << std::endl;
    }

    client.blockchain_fetch_history3(on_error, on_done, wallet_.childAddress(child_id_));
    client.wait();

    return account_balance;
}

bool Client::setState(ConstStatePtr& new_state)
{
    if(new_state == nullptr || !new_state->checkSignature(provider_pk_))
        return false;

    if(latest_state_ != nullptr && !new_state->isUpdateTo(latest_state_))
        return false;

    latest_state_ = new_state;

    return true;
}

void Client::setProviderPk(ConstPubEcKeyPtr provider_pk)
{
    provider_pk_ = std::move(provider_pk);
}

void Client::setDepositHash(hash_digest tx_hash)
{
    deposit_hash_ = tx_hash;
}

void Client::setDepositValue(uint64_t value)
{
    deposit_value_ = value;
}

void Client::setProviderAddress(bc::wallet::payment_address provider_address)
{
    provider_address_ = provider_address;
}

void Client::setLockTime(uint64_t new_lock_time)
{
    lock_time_ = new_lock_time;
}

void Client::setTransactionBalance(hash_digest tx_hash, uint32_t index)
{
    client::connection_type connection = {};
    connection.retries = 3;
    connection.timeout_seconds = 8;
    connection.server = config::endpoint(LIBBITCOIN_TESTNET_SERVER);

    client::obelisk_client client(connection);

    balance_ = 0;
    bc::chain::transaction transaction;

    const auto on_done = [&transaction](const chain::transaction& fetched_tx){
        transaction = fetched_tx;
    };

    static const auto on_error = [](const code& ec){
        std::cout << "Error Code: " << ec.message() << std::endl;
    };

    if(!client.connect(connection))
    {
        std::cout << "Fail" << std::endl;
    }
    else
    {
        if(VERBOSE && CLIENT_VERBOSE)
            std::cout << "\nConnection Succeeded" << std::endl;
    }

    client.blockchain_fetch_transaction(on_error, on_done, tx_hash);
    client.wait();

    if(transaction.outputs().size() > index)
        balance_ = transaction.outputs()[index].value();
}

hash_digest Client::createDeposit(const std::string& utxo_hash_string, uint32_t utxo_index, uint64_t satoshi_to_spend,
                                  bc::wallet::payment_address destination_address, uint64_t lock_time)
{
    hash_digest utxo_hash;
    decode_hash(utxo_hash, utxo_hash_string);

    setTransactionBalance(utxo_hash, utxo_index);
    if(balance_ < satoshi_to_spend)
    {
        std::cout << "can only spent up to " << balance_ << " satoshis" << std::endl;
        return null_hash;
    }

    provider_address_ = destination_address;
    deposit_value_ = satoshi_to_spend;
    lock_time_ = lock_time;

    //construct input
    bc::chain::transaction deposit_tx = bc::chain::transaction();
    deposit_tx.set_locktime(0);
    deposit_tx.set_version(1);

    bc::chain::input input1 = bc::chain::input();
    bc::chain::output_point utxo(utxo_hash, utxo_index);
    input1.set_previous_output(utxo);
    input1.set_sequence(0);
    deposit_tx.inputs().push_back(input1);

    //construct output
    bc::chain::script cltv_script = bc::chain::script();
    std::string script_string = createDepositRedeemScript(provider_address_.hash(), wallet_.childAddress(child_id_).hash(), lock_time_);
    cltv_script.from_string(script_string);
    bc::wallet::payment_address cltv_address(cltv_script);

    bc::chain::script output_script(bc::chain::script().to_pay_script_hash_pattern(cltv_address.hash()));
    bc::chain::output output1(deposit_value_, output_script);
    deposit_tx.outputs().push_back(output1);

    bc::chain::script output_self = bc::chain::script(bc::chain::script().to_pay_key_hash_pattern(wallet_.childAddress(child_id_).hash()));
    bc::chain::output output2(balance_ - deposit_value_ - TRANSACTION_FEE, output_self);
    deposit_tx.outputs().push_back(output2);

    //sign transaction
    endorsement sig;
    bc::chain::script redeem_script = bc::chain::script(bc::chain::script().to_pay_key_hash_pattern(wallet_.childAddress(child_id_).hash()));
    bc::chain::script().create_endorsement(sig, wallet_.childPrivateKey(child_id_).secret(), redeem_script, deposit_tx, 0u, bc::machine::all);

    machine::operation::list sig_script;
    sig_script.push_back(machine::operation(sig));
    sig_script.push_back(machine::operation(to_chunk(wallet_.childPublicKey(child_id_).point())));
    bc::chain::script unlocking_script(sig_script);

    deposit_tx.inputs()[0].set_script(unlocking_script);

    wallet_.broadcastTransaction(deposit_tx);

    if(VERBOSE && CLIENT_VERBOSE)
        displayNewDeposit(deposit_tx);

    deposit_hash_ = deposit_tx.hash();

    return deposit_hash_;
}

ConstTransactionPtr Client::makeOfflineTransaction(const uint64_t satoshi_to_spent,
                                                   const std::array<uint8_t, RND_NR_SIZE_BYTES> &rnd_nr)
{
    if(latest_state_ == nullptr)
        return ConstTransactionPtr(nullptr);

    const StateData state_data = latest_state_->getData();
    uint64_t satoshi_already_spent = state_data.getSpent();
    if(satoshi_already_spent + satoshi_to_spent > state_data.getLimit())
    {
        if(VERBOSE && CLIENT_VERBOSE)
            std::cout << "\n(client) error: can't spent that much Satoshi" << std::endl;

        return ConstTransactionPtr(nullptr);
    }

    bc::chain::transaction tx = getSignedBcTransaction(satoshi_already_spent + satoshi_to_spent);

    uint32_t rev_nr = state_data.getRevisionNr();
    TransactionPtr transaction = std::make_shared<Transaction>(tx, rev_nr, rnd_nr);

    ConstDapsSigPtr daps_signature = signOfflineTransaction(transaction);
    if(daps_signature == nullptr)
    {
        if(VERBOSE && CLIENT_VERBOSE)
            std::cout << "\n(client) error: can't create a daps signature for the new transaction" << std::endl;

        return ConstTransactionPtr(nullptr);
    }

    transaction->setSignature(daps_signature);

    if(VERBOSE && CLIENT_VERBOSE)
        displayNewTransaction(transaction);

    return transaction;
}

bc::chain::transaction Client::getSignedBcTransaction(uint64_t satoshi)
{
    //construct input
    bc::chain::transaction new_tx = bc::chain::transaction();
    bc::chain::output_point utxo(deposit_hash_, 0);

    bc::chain::input input1 = bc::chain::input();
    input1.set_previous_output(utxo);
    input1.set_sequence(0xffffffff);
    new_tx.inputs().push_back(input1);

    //construct output
    bc::chain::script output_provider = bc::chain::script(bc::chain::script().to_pay_key_hash_pattern(provider_address_.hash()));
    bc::chain::output output1(satoshi, output_provider);
    new_tx.outputs().push_back(output1);

    bc::chain::script output_self = bc::chain::script(bc::chain::script().to_pay_key_hash_pattern(wallet_.childAddress(child_id_).hash()));
    bc::chain::output output2(deposit_value_ - satoshi - TRANSACTION_FEE, output_self);
    new_tx.outputs().push_back(output2);

    //sign transaction
    bc::chain::script cltv_script = bc::chain::script();
    std::string script_string = createDepositRedeemScript(provider_address_.hash(), wallet_.childAddress(child_id_).hash(), lock_time_);
    cltv_script.from_string(script_string);

    endorsement sig;
    bc::chain::script().create_endorsement(sig, wallet_.childPrivateKey(child_id_).secret(), cltv_script, new_tx, 0u, bc::machine::all);

    machine::operation::list sig_script;
    sig_script.push_back(machine::operation(sig));
    sig_script.push_back(machine::operation(to_chunk(wallet_.childPublicKey(child_id_).point())));
    bc::chain::script unlocking_script(sig_script);

    new_tx.inputs()[0].set_script(unlocking_script);

    return new_tx;
}

ConstDapsSigPtr Client::signOfflineTransaction(TransactionPtr &transaction)
{
    std::vector<uint8_t> bytes = transaction->getData().getBytes();
    DapsMessage* msg = dapsMsgNew(transaction->getData().getRevisionNumber(), &(bytes[0]), bytes.size());

    auto deleteDapsSig = [](DapsSignature* sign){dapsSignatureFree(&sign);};
    DapsSigPtr signature = DapsSigPtr(dapsSignatureNew(daps_pk_.get()), deleteDapsSig);

    if(dapsSign(signature.get(), daps_sk_.get(), daps_pk_.get(), msg) != SUCCESS)
    {
        dapsMsgFree(&msg);
        return nullptr;
    }

    dapsMsgFree(&msg);
    return signature;
}

void Client::reclaimDeposit() const
{
    //construct input
    bc::chain::transaction reclaim_tx = bc::chain::transaction();
    reclaim_tx.set_version(1);
    reclaim_tx.set_locktime(lock_time_+ 3600);

    bc::chain::input input1 = bc::chain::input();
    bc::chain::output_point utxo(deposit_hash_, 0);
    input1.set_previous_output(utxo);
    input1.set_sequence(0);
    reclaim_tx.inputs().push_back(input1);

    //construct output
    bc::chain::script output_self = bc::chain::script(bc::chain::script().to_pay_key_hash_pattern(wallet_.childAddress(child_id_).hash()));
    bc::chain::output output1(deposit_value_ - TRANSACTION_FEE, output_self);
    reclaim_tx.outputs().push_back(output1);

    //sign transaction
    bc::chain::script cltv_script = bc::chain::script();
    std::string script_string = createDepositRedeemScript(provider_address_.hash(), wallet_.childAddress(child_id_).hash(), lock_time_);
    cltv_script.from_string(script_string);

    endorsement sig;
    bc::chain::script().create_endorsement(sig, wallet_.childPrivateKey(child_id_).secret(), cltv_script, reclaim_tx, 0u, bc::machine::all);

    machine::operation::list sig_script;
    sig_script.push_back(machine::operation(sig));
    sig_script.push_back(machine::operation(to_chunk(wallet_.childPublicKey(child_id_).point())));
    sig_script.push_back(machine::operation(bc::machine::opcode(0)));
    sig_script.push_back(machine::operation(cltv_script.to_data(false)));
    bc::chain::script unlocking_script(sig_script);

    reclaim_tx.inputs()[0].set_script(unlocking_script);

    wallet_.broadcastTransaction(reclaim_tx);
}

std::string Client::createDepositRedeemScript(const short_hash& provider_address,
                                              const short_hash& client_address, uint64_t lock_time)
{
    data_chunk lock_time_chunk(4);
    memcpy(&(lock_time_chunk[0]), &lock_time, 4);

    std::string script_string = "if dup hash160 [" + encode_base16(provider_address) +
                                "] equalverify checksigverify else [" + encode_base16(lock_time_chunk) +
                                "] checklocktimeverify drop endif dup hash160 [" +
                                encode_base16(client_address) + "] equalverify checksig";

    return script_string;
}

void Client::displayNewClient() const
{
    std::cout << "\nNew Client (id = " << id_ << "):" << std::endl;
    std::cout << "Mnemonic:" << std::endl;
    wallet_.displayMnemonic();
    wallet_.displayAddress(child_id_);
}

void Client::displayNewDeposit(chain::transaction deposit_tx) const
{
    std::cout << "\nNew Deposit (client id = " << id_ << "):" << std::endl;

    std::cout << "transaction hash:" << std::endl;
    std::cout << encode_hash(deposit_tx.hash()) << std::endl;

    std::cout << "input transaction:" << std::endl;
    for(const bc::chain::input& in : deposit_tx.inputs())
        std::cout << encode_hash(in.previous_output().hash()) << " index: " << in.previous_output().index() << std::endl;

    std::cout << "output adresses:" << std::endl;
    for(const bc::chain::output& out : deposit_tx.outputs())
        std::cout << out.address(bc::wallet::payment_address::testnet_p2kh) << " : " << out.value() << " Satoshis" << std::endl;
}

void Client::displayNewTransaction(TransactionPtr& transaction) const
{
    std::cout << "\nNew Transaction (client id = " << id_ << "):" << std::endl;
    transaction->display();
}