//----------------------------------------------------------------------------------------------------------------------
// Code adapted from:
//
// Title: speed.c
// Author: OpenSSL contributors
// Date: 2017
// Availability: https://github.com/openssl/openssl/blob/master/apps/speed.c
//----------------------------------------------------------------------------------------------------------------------

#include <openssl/err.h>
#include <openssl/rand.h>
#include "gtest/gtest.h"

extern "C"
{
#include<sys/times.h>

#include"daps.h"
}

#define NUM_ADDRESSES (10)
#define ADDRESS_TO_SIGN (5)

#define START 0
#define STOP  1

# define TM_START 0
# define TM_STOP  1

#undef SECONDS
#define SECONDS 10

#define SIZE_NUM 1

static const int lengths[SIZE_NUM] = {
        16//, 64, 256, 1024, 8 * 1024, 16 * 1024
};

static int usertime = 1;

static int mr = 0;

static volatile int run = 0;

static double results[SIZE_NUM];

#ifdef SIGALRM
# if defined(__STDC__) || defined(sgi) || defined(_AIX)
#  define SIGRETTYPE void
# else
#  define SIGRETTYPE int
# endif

static SIGRETTYPE sig_done(int sig);
static SIGRETTYPE sig_done(int sig)
{
    signal(SIGALRM, sig_done);
    run = 0;
}
#endif

double app_tminterval(int stop, int usertime)
{
    double ret = 0;
    struct tms rus;
    clock_t now = times(&rus);
    static clock_t tmstart;

    if (usertime)
        now = rus.tms_utime;

    if (stop == TM_START)
        tmstart = now;
    else {
        long int tck = sysconf(_SC_CLK_TCK);
        ret = (now - tmstart) / (double)tck;
    }

    return (ret);
}

static void print_message(const char *s, int length)
{
    printf(mr ? "+DT:%s:%d:%d\n"
              : "Doing %s for %ds on %d size blocks: ", s, SECONDS, length);
    alarm(SECONDS);
}

static void print_result(int alg, int run_no, int count, double time_used)
{
    if (count == -1) {
        perror("EVP error\n");
        exit(1);
    }
    printf(mr ? "+R:%d:%s:%f\n"
              : "%d %s's in %.2fs\n", count, "DAPS", time_used);
    results[run_no] = ((double)count) / time_used * lengths[run_no];
}

static double Time_F(int s)
{
    double ret = app_tminterval(s, usertime);
    if (s == STOP)
        alarm(0);
    return ret;
}

TEST(speed_test, speed_sign)
{
    signal(SIGALRM, sig_done);

    DapsPK* pk = dapsPkNew();
    DapsSK* sk = dapsSkNew();
    DapsMessage* msg = (DapsMessage*)calloc(1, sizeof(DapsMessage));

    msg->i_ = ADDRESS_TO_SIGN;
    msg->p_ = (uint8_t*)malloc(1);

    dapsKeyGen(sk, pk, NUM_ADDRESSES);
    DapsSignature* sign = dapsSignatureNew(pk);

    double d;
    int count;

    for(int testnum = 0; testnum < SIZE_NUM; testnum++)
    {
        print_message("DAPS sign", lengths[testnum]);
        msg->p_length_ = (size_t)lengths[testnum];
        msg->p_ = (uint8_t*)realloc(msg->p_, msg->p_length_);
        RAND_bytes(msg->p_, lengths[testnum]);

        Time_F(START);
        for (count = 0, run = 1; run == 1; count++)
        {
            dapsSign(sign, sk, pk, msg);
        }
        d = Time_F(STOP);
        print_result(0, testnum, count, d);
    }

    dapsSkFree(&sk);
    dapsPkFree(&pk);
    dapsMsgFree(&msg);
    dapsSignatureFree(&sign);
}

TEST(speed_test, speed_verify)
{
    signal(SIGALRM, sig_done);

    DapsPK* pk = dapsPkNew();
    DapsSK* sk = dapsSkNew();
    DapsMessage* msg = (DapsMessage*)calloc(1, sizeof(DapsMessage));

    msg->i_ = ADDRESS_TO_SIGN;
    msg->p_ = (uint8_t*)malloc(1);

    dapsKeyGen(sk, pk, NUM_ADDRESSES);
    DapsSignature* sign = dapsSignatureNew(pk);

    double d;
    int count;

    for(int testnum = 0; testnum < SIZE_NUM; testnum++)
    {
        print_message("DAPS verify", lengths[testnum]);
        msg->p_length_ = (size_t)lengths[testnum];
        msg->p_ = (uint8_t*)realloc(msg->p_, msg->p_length_);
        RAND_bytes(msg->p_, lengths[testnum]);
        dapsSign(sign, sk, pk, msg);

        Time_F(START);
        for (count = 0, run = 1; run == 1; count++)
        {
            dapsVerify(pk, msg, sign);
        }
        d = Time_F(STOP);
        print_result(0, testnum, count, d);
    }

    dapsSkFree(&sk);
    dapsPkFree(&pk);
    dapsMsgFree(&msg);
    dapsSignatureFree(&sign);
}