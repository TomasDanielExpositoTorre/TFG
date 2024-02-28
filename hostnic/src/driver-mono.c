#define _GNU_SOURCE
#include "selcap.h"
#include "sighandling.h"
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>

const char *argp_program_version = "HostNic Mono 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"if", 'i', "name", 0, "Interface used to capture packets."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    Arguments *args = state->input;

    switch (key)
    {
    case 'i':
        args->interface = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, NULL};
static pcap_t *handle;
static volatile int signaled = 0;

void sighandler(int signal)
{
    signaled = 1;
    pcap_breakloop(handle);
    printf("\nSIGNAL received, stopping packet capture...\n");
}

void *logging_thread(void *args)
{
    LoggingInfo *log = (LoggingInfo *)args;
    sleep(5);

    while (signaled == 0)
    {
        capping_log(log);
        sleep(5);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    Arguments args;
    pthread_attr_t attr;
    pthread_t logger;
    sigset_t thread_mask;
    char error_buff[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* Block SIGINT for all threads except master */
    set_mask(thread_mask, SIGINT);

    if (block_signal(SIGINT) ||
        install_handler(SIGINT, sighandler) ||
        unblock_signal(SIGINT))
    {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    if (pthread_attr_init(&attr) ||
        pthread_attr_setsigmask_np(&attr, &thread_mask) ||
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
    {
        fprintf(stderr, "Could not initialize children threads.\n");
        return EXIT_FAILURE;
    }

    /* Initialize variables and PCAP */
    args_init((&args), 45, 15);
    log_init((&(args.log)));
    psem_init(args.log.log_mutex);

    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_lookupnet(args.interface, &net, &mask, error_buff) == -1)
        net = PCAP_NETMASK_UNKNOWN;

    /* Initialize packet capture handle and file */
    handle = pcap_open_live(args.interface, PCAP_BUFSIZE, 1, TO_MS_VAL, error_buff);
    if (handle == NULL)
    {
        fprintf(stderr, "[Error:Interface] Couldn't open %s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "[Error:Interface] %s doesn't provide Ethernet headers\n", args.interface);
        return EXIT_FAILURE;
    }
    if (pcap_compile(handle, &fp, filter_exp, 0, net) || pcap_setfilter(handle, &fp))
    {
        fprintf(stderr, "[Error:Filter] %s: %s\n", filter_exp, pcap_geterr(handle));
        return EXIT_FAILURE;
    }
#ifndef __SIMSTORAGE
    args.file = pcap_dump_open(handle, "../driver-mono.pcap");
#endif

    /*
        Parent - capture packets
        Child - log capture statistics
    */
    pthread_create(&logger, &attr, logging_thread, (void *)&(args.log));
    pcap_loop(handle, -1, selective_capping, (unsigned char *)&(args));

    /* Close data and exit */
    pcap_close(handle);
#ifndef __SIMSTORAGE
    pcap_dump_flush(args.file);
    pcap_dump_close(args.file);
#endif
    pthread_attr_destroy(&attr);

    psem_destroy(args.log.log_mutex);

    return EXIT_SUCCESS;
}