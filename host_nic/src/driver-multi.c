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
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    ThreadArguments *t_args = state->input;

    switch (key)
    {
    case 'i':
        t_args->args.interface = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, NULL};
static ThreadArguments t_args;

void sighandler(int signal)
{
    t_args.signaled = 1;
    printf("\nSIGNAL received, stopping packet capture...\n");
}

int main(int argc, char **argv)
{
    pthread_attr_t attr;
    pthread_t *threads;
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
        pthread_attr_setsigmask_np(&attr, &thread_mask))
    {
        fprintf(stderr, "Could not initialize children threads.\n");
        return EXIT_FAILURE;
    }

    /* Initialize variables and PCAP */
    if ((threads = (pthread_t *)malloc(NTHREADS * sizeof(threads[0]))) == NULL)
        return EXIT_FAILURE;

    args_init((&t_args.args), 45, 15);
    log_init((&(t_args.args.log)));
    psem_init(t_args.read_mutex);
    psem_init(t_args.write_mutex);
    psem_init(t_args.args.log.log_mutex);

    argp_parse(&argp, argc, argv, 0, 0, &t_args);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_lookupnet(t_args.args.interface, &net, &mask, error_buff) == -1)
    {
        fprintf(stderr, "[Error:Interface] Can't get netmask for %s\n", t_args.args.interface);
        return EXIT_FAILURE;
    }

    /* Initialize packet capture handle and file */
    t_args.handle = pcap_open_live(t_args.args.interface, ETH_FRAME_LEN, 1, 10, error_buff);

    if (t_args.handle == NULL)
    {
        fprintf(stderr, "Couldn't open interface %s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_datalink(t_args.handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", t_args.args.interface);
        return EXIT_FAILURE;
    }
    if (pcap_compile(t_args.handle, &fp, filter_exp, 0, net) || pcap_setfilter(t_args.handle, &fp))
    {
        fprintf(stderr, "[Error:Filter] %s: %s\n", filter_exp, pcap_geterr(t_args.handle));
        return EXIT_FAILURE;
    }
    t_args.args.file = pcap_dump_open(t_args.handle, "../driver-multi.pcap");

    /*
        Parent - log capture statistics
        Children - capture packets
    */
    for (int i = 0; i < NTHREADS; i++)
        pthread_create(threads + i, &attr, selective_capping_thread, (void *)&(t_args));

    sleep(5);
    while (t_args.signaled == 0)
    {
        capping_log(&(t_args.args.log));
        sleep(5);
    }

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(*(threads + i), NULL);

    /* Close data and exit */
    free(threads);
    pcap_close(t_args.handle);
    pthread_attr_destroy(&attr);
    pcap_dump_flush(t_args.args.file);
    pcap_dump_close(t_args.args.file);

    psem_destroy(t_args.read_mutex);
    psem_destroy(t_args.write_mutex);
    psem_destroy(t_args.args.log.log_mutex);

    return EXIT_SUCCESS;
}