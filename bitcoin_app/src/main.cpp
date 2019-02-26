
#include <bitcoin/bitcoin.hpp>
#include <bitcoin/client.hpp>

#include "provider.h"
#include "client.h"

using namespace bc;

#define CLIENT_ID 0
#define NUM_ADDRESSES 10
#define NUM_POINTS_OF_SALE 5

const char PROVIDER_MNEMONIC[] = "equip address calm seed priority garden fade thing axis used couch abuse";
const char CLIENT_MNEMONIC[] = "shop convince absorb invite black myself harsh mother skin subject supply prefer";

//Dialog defines
#define START_CREATE_DEPOSIT_ONLY 1
#define START_CREATE_DEPOSIT_AND_PAY 2
#define START_RESTORE_DEPOSIT_AND_PAY 3
#define START_EXIT 4

#define MAIN_MAKE_TRANSACTION 1
#define MAIN_DOUBLE_SPENT 2
#define MAIN_CLOSE_DEPOSIT 3
#define MAIN_RECLAIM_DEPOSIT 4
#define MAIN_EXIT 5

void displayStartDialog()
{
    std::cout << "\nPlease choose an option:" << std::endl;
    std::cout << "1) create a deposit only" << std::endl;
    std::cout << "2) create a deposit and make payments" << std::endl;
    std::cout << "3) make payments with an existing deposit" << std::endl;
    std::cout << "4) exit" << std::endl;
}

void displayMainDialog()
{
    std::cout << "\nPlease choose an option:" << std::endl;
    std::cout << "1) make transactions" << std::endl;
    std::cout << "2) double-spent" << std::endl;
    std::cout << "3) close deposit" << std::endl;
    std::cout << "4) reclaim deposit" << std::endl;
    std::cout << "5) exit" << std::endl;
}

int getIntegerInput()
{
    std::string input;
    getline(cin, input);
    return atoi(input.c_str());
}

uint64_t getSatoshiFromInput()
{
    std::string input;
    getline(cin, input);

    uint64_t satoshis;
    decode_base10(satoshis, input, 0);
    return satoshis;
}

int main()
{
    //create client and provider
    Provider provider(split(PROVIDER_MNEMONIC));
    Client client(CLIENT_ID, NUM_ADDRESSES, split(CLIENT_MNEMONIC));

    //exchange public keys
    ConstPubEcKeyPtr provider_pk = provider.getPublicEcKey();
    client.setProviderPk(provider_pk);
    provider.addClient(client.getId(), client.getDapsPk());

    //create points of sale
    std::vector<PoSPtr> points_of_sale;
    const wallet::payment_address provider_addr = provider.getPaymentAddress();
    std::map<uint32_t, ConstDapsPkPtr> clients = provider.getClientDapsPKs();
    for(uint32_t i = 0; i < NUM_POINTS_OF_SALE; ++i)
    {
        PoSPtr pos = std::make_shared<PointOfSale>(clients, provider_pk, i, provider_addr);
        ConstPubEcKeyPtr pos_pk = pos->getPublicEcKey();
        pos->setEcKeySignature(provider.signEcKey(pos_pk));
        points_of_sale.push_back(pos);
    }

    std::cout << "\nthe number of transactions (addresses for the DAPS) is currently set to: " << NUM_ADDRESSES;
    std::cout << std::endl;

    displayStartDialog();
    int choice = getIntegerInput();

    if(choice <= 0 || choice >= START_EXIT)
    {
        std::cout << "exiting" << std::endl;
        return 0;
    }

    hash_digest deposit_tx_hash;
    uint64_t lock_time;

    if(choice == START_CREATE_DEPOSIT_ONLY || choice == START_CREATE_DEPOSIT_AND_PAY)
    {
        //create deposit
        std::cout << "please enter the hash of a transaction with an unspend transaction output (utxo) to create the deposit:" << std::endl;
        std::string utxo_hash;
        getline(cin, utxo_hash);

        std::cout << "please enter the output index of the utxo: ";
        uint32_t output_index = (uint32_t)getIntegerInput();

        //check balance
        uint64_t client_balance = client.getClientBalance();
        if(client_balance == 0)
        {
            std::cout << "client balance is 0 or connection to libbitcoin server failed" << std::endl;
            return 0;
        }

        std::cout << "please enter the amount of Satoshi (1 Bitcoin = 100,000,000 Satoshi) to spent: ";
        uint64_t satoshis = getSatoshiFromInput();
        while(satoshis >= client_balance)
        {
            std::cout << "cannot spent more than " << client_balance << " Satoshi" << std::endl
                      << "enter a new amount: ";
            satoshis = getSatoshiFromInput();
        }

        std::cout << "please enter the lock time for the deposit in days: ";
        uint64_t now = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
        lock_time = now + getIntegerInput() * 86400;

        std::cout << "the deposit is locked until " << lock_time << " unix time. Please note the time or otherwise the "
                "deposit will become unspendable once the application has exited." << std::endl;

        deposit_tx_hash = client.createDeposit(utxo_hash, output_index, satoshis, provider_addr, lock_time);

        if(deposit_tx_hash == null_hash)
        {
            std::cout << "\nfailed to create deposit." << std::endl;
            return 0;
        }

        if(choice == START_CREATE_DEPOSIT_ONLY)
        {
            std::cout << "\ndeposit created" << std::endl;
            return 0;
        }
    }
    else
    {
        //restore deposit
        std::cout << "please enter the deposit transaction hash:" << std::endl;
        std::string tx_hash_string;
        getline(cin, tx_hash_string);

        decode_hash(deposit_tx_hash, tx_hash_string);
        client.setDepositHash(deposit_tx_hash);

        std::cout << "please enter the lock time of the deposit: ";
        lock_time = (uint64_t)getIntegerInput();
        client.setLockTime(lock_time);

        std::cout << "please enter the amount of Satoshi (1 Bitcoin = 100,000,000 Satoshi) placed in the deposit: ";
        uint64_t spendable_satoshis = (uint64_t)getIntegerInput();
        client.setDepositValue(spendable_satoshis);

        client.setProviderAddress(provider_addr);
    }


    //get initial state from provider
    ConstStatePtr state = provider.getInitialState(deposit_tx_hash, client.getId(), lock_time, client.getAddressHash());
    while(state == nullptr)
    {
        std::cout << "error creating initial state" << std::endl;
        std::cout << "do you want to try again? (0 = yes, 1 = no)" << std::endl;
        choice = getIntegerInput();
        if(choice == 1)
            return 0;

        state = provider.getInitialState(deposit_tx_hash, client.getId(), lock_time, client.getAddressHash());
    }

    client.setState(state);

    displayMainDialog();
    choice = getIntegerInput();

    while(choice == MAIN_MAKE_TRANSACTION || choice == MAIN_DOUBLE_SPENT)
    {
        //make offline transactions
        std::cout << "please choose a point of sale (0 - " << NUM_POINTS_OF_SALE - 1 << "): ";
        uint32_t pos_index = (uint32_t)getIntegerInput();
        if(pos_index >= NUM_POINTS_OF_SALE)
        {
            std::cout << "invalid point of sale" << std::endl;
            continue;
        }

        std::cout << "please enter Satoshi (1 Bitcoin = 100,000,000 Satoshi) to spent: ";
        uint64_t satoshis_to_spent = (uint64_t)getIntegerInput();

        std::array<uint8_t, RND_NR_SIZE_BYTES> random_nr = points_of_sale[pos_index]->getNewRandomNr();
        ConstTransactionPtr transaction = client.makeOfflineTransaction(satoshis_to_spent, random_nr);

        ConstStatePtr client_state = client.getLatestState();
        ConstStatePtr new_state = points_of_sale[pos_index]->receiveOfflineTransaction(transaction, client_state);

        //if we don't want to double-spent set the new state
        if(choice == MAIN_MAKE_TRANSACTION)
            client.setState(new_state);

        displayMainDialog();
        choice = getIntegerInput();
    }

    if(choice <= 0 || choice >= MAIN_EXIT)
        return 0;

    if(choice == MAIN_CLOSE_DEPOSIT)
    {
        //collect transactions
        std::vector<ConstTransactionPtr> transactions;
        for(int i = 0; i < NUM_POINTS_OF_SALE; ++i)
        {
            std::vector<ConstTransactionPtr> pos_transactions = points_of_sale[i]->getTransactions();
            transactions.insert(transactions.end(), pos_transactions.begin(), pos_transactions.end());
        }
        provider.retrieveBitcoin(transactions, client.getId());
    }
    else if(choice == MAIN_RECLAIM_DEPOSIT)
    {
        client.reclaimDeposit();
    }

    std::cout << "exiting" << std::endl;
    return 0;
}