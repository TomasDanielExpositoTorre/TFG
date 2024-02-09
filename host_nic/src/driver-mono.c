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
    {"percentage", 'p', "int", 0, "Percentage of total ASCII required per packet."},
    {"threshold", 't', "int", 0, "Consecutive ASCII required per packet."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    Arguments *args = state->input;

    switch (key)
    {
    case 'i':
        args->interface = arg;
        break;
    case 'p':
        args->percentage = (uint8_t)atoi(arg);
        break;
    case 't':
        args->threshold = (uint8_t)atoi(arg);
        break;
    case ARGP_KEY_END:
        if (args->percentage <= 0 || args->percentage > 100)
        {
            fprintf(stdout, "Given percentage must be a value between 1 and 100.\n");
            exit(EXIT_FAILURE);
        }
        if (args->threshold == 0)
        {
            fprintf(stdout, "Given threshold must be a value greater than 0.\n");
            exit(EXIT_FAILURE);
        }

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
    sleep(5);

    while (signaled == 0)
    {
        capping_log(args);
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
        fprintf(stderr, "Could not- initialize children threads.\n");
        return EXIT_FAILURE;
    }

    args.percentage = 45;
    args.threshold = 15;
    args.interface = NULL;
    args.log.packets = 0;
    args.log.total_bytes = 0;
    args.log.captured_bytes = 0;
    args.log.elapsed_time = 0;
    argp_parse(&argp, argc, argv, 0, 0, &args);
    pthread_mutex_init(&(args.log.log_mutex), NULL);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }

    handle = pcap_open_live(args.interface, ETH_FRAME_LEN, 1, 10, error_buff);

    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open interface %s\n", error_buff);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported", args.interface);
        return EXIT_FAILURE;
    }

    args.file = pcap_dump_open(handle, "../driver-mono.pcap");

    pthread_create(&logger, &attr, logging_thread, (void *)&(args.log));
    pcap_loop(handle, -1, selective_capping, (unsigned char *)&(args));

    pcap_close(handle);
    pcap_dump_flush(args.file);
    pcap_dump_close(args.file);
    pthread_mutex_destroy(&(args.log.log_mutex));

    return EXIT_SUCCESS;
}