#define _GNU_SOURCE
#include "selcap.h"
#include "sighandling.h"
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <pthread.h>


const char *argp_program_version = "HostNic Multi 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"if", 'i', "name", 0, "Interface used to capture packets."},
    {"percentage", 'p', "int", 0, "Percentage of total ASCII required per packet."},
    {"threshold", 't', "int", 0, "Consecutive ASCII required per packet."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    ThreadArgs *t_args = state->input;

    switch (key)
    {
    case 'i':
        t_args->h_args.interface = arg;
        break;
    case 'p':
        t_args->h_args.percentage = (uint8_t)atoi(arg);
        break;
    case 't':
        t_args->h_args.threshold = (uint8_t)atoi(arg);
        break;
    case ARGP_KEY_END:
        if (t_args->h_args.percentage <= 0 || t_args->h_args.percentage > 100)
        {
            fprintf(stdout, "Given percentage must be a value between 1 and 100.\n");
            exit(EXIT_FAILURE);
        }
        if (t_args->h_args.threshold == 0)
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
static ThreadArgs t_args;

void sighandler(int signal)
{
    t_args.signaled = 1;
    printf("\nSIGNAL received, stopping packet capture...\n");
}

int main(int argc, char **argv)
{
    char error_buff[PCAP_ERRBUF_SIZE];
    pthread_t *threads;
    pthread_attr_t attr;
    sigset_t mask;
    sigset_t thread_mask;

    /* Block SIGINT for all threads except master */
    fill_mask_except(mask, SIGINT);
    set_mask(thread_mask, SIGINT);

    if (block_signal(SIGINT) | install_handler(SIGINT, sighandler) | unblock_signal(SIGINT))
    {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    if (pthread_attr_init(&attr) | pthread_attr_setsigmask_np(&attr, &thread_mask))
    {
        fprintf(stderr, "Could not initialize children threads.\n");
        return EXIT_FAILURE;
    }

    if ((threads = (pthread_t *)malloc(NTHREADS * sizeof(threads[0]))) == NULL)
        return EXIT_FAILURE;
    pthread_mutex_init(&(t_args.pmutex), NULL);
    
    t_args.h_args.percentage = 45;
    t_args.h_args.threshold = 15;
    t_args.h_args.interface = NULL;
    argp_parse(&argp, argc, argv, 0, 0, &t_args);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }

    t_args.handle = pcap_open_live(t_args.h_args.interface, ETH_FRAME_LEN, 1, 1000, error_buff);

    if (t_args.handle == NULL)
    {
        fprintf(stderr, "Couldn't open interface %s\n", error_buff);
        return EXIT_FAILURE;
    }

    if (pcap_datalink(t_args.handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", t_args.h_args.interface);
        return EXIT_FAILURE;
    }
    
    for(int i = 0; i < NTHREADS; i++)
        pthread_create(threads + i, &attr, selective_capping_thread, (void*)&(t_args));

    sigsuspend(&mask);

    for(int i = 0; i < NTHREADS; i++)
        pthread_join(*(threads + i), NULL);

    pthread_attr_destroy(&attr);
    pthread_mutex_destroy(&(t_args.pmutex));
    pcap_close(t_args.handle);
    free(threads);
    return EXIT_SUCCESS;
}