#define _GNU_SOURCE
#define NTHREADS 32
#include "headers.h"

const char *argp_program_version = "HostNic Multi 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"interface", 'i', "name", 0, "Interface used to capture packets."},
    {"output", 'o', "path", 0, "File where captured packets will be dumped."},
    {"input", 'd', "path", 0, "File to read packets from."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct thread_arguments *targs = state->input;

    switch (key)
    {
    case 'i':
        targs->args.interface = arg;
        break;
    case 'o':
        targs->args.output = arg;
        break;
    case 'd':
        targs->args.input = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, NULL};
static struct thread_arguments targs;

void sighandler(int signal)
{
    targs.signaled = true;
    printf("\nSIGNAL received, stopping packet capture...\n");
}

int main(int argc, char **argv)
{
    pthread_attr_t attr;
    pthread_t threads[NTHREADS];
    sigset_t thread_mask;
    char error_buff[PCAP_ERRBUF_SIZE];

    struct bpf_program fp;
    char filter_exp[] = "tcp or udp";
    bpf_u_int32 mask;
    bpf_u_int32 net;

    /* Block SIGINT for all threads except master */
    set_mask(thread_mask, SIGINT);
    signal(SIGINT, sighandler);

    if (pthread_attr_init(&attr) ||
        pthread_attr_setsigmask_np(&attr, &thread_mask))
    {
        fprintf(stderr, "Could not initialize children threads.\n");
        return EXIT_FAILURE;
    }

    args_init((&targs.args), 45, 15);
    log_init((&(targs.args.log)));
    psem_init(targs.read_mutex);
    psem_init(targs.write_mutex);
    psem_init(targs.args.log.log_mutex);

    argp_parse(&argp, argc, argv, 0, 0, &targs);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_lookupnet(targs.args.interface, &net, &mask, error_buff) == -1)
        net = PCAP_NETMASK_UNKNOWN;

    /* Initialize packet capture handle and file */
    if (targs.args.input == NULL)
    {
        if (pcap_lookupnet(targs.args.interface, &net, &mask, error_buff) == -1)
            net = PCAP_NETMASK_UNKNOWN;
        targs.handle = pcap_open_live(targs.args.interface, PCAP_BUFSIZE, 1, TO_MS_VAL, error_buff);
    }
    else
        targs.handle = pcap_open_offline(targs.args.input, error_buff);

    if (targs.handle == NULL)
    {
        fprintf(stderr, "Couldn't open interface %s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_datalink(targs.handle) != DLT_EN10MB)
    {
        fprintf(stderr, "Device %s doesn't provide Ethernet headers - not supported.\n", targs.args.interface);
        pcap_close(targs.handle);
        return EXIT_FAILURE;
    }
    if (targs.args.input == NULL && (pcap_compile(targs.handle, &fp, filter_exp, 0, net) || pcap_setfilter(targs.handle, &fp)))
    {
        fprintf(stderr, "[Error:Filter] %s: %s\n", filter_exp, pcap_geterr(targs.handle));
        pcap_close(targs.handle);
        return EXIT_FAILURE;
    }

#ifndef __SIMSTORAGE
    if (targs.args.output == NULL)
    {
        fprintf(stderr, "[Error:Dumping] Please provide a file path to dump captured packets\n");
        pcap_close(targs.handle);
        return EXIT_FAILURE;
    }
    targs.args.file = pcap_dump_open(targs.handle, targs.args.output);
#endif

    /*
        Parent - log capture statistics
        Children - capture packets
    */
    for (int i = 0; i < NTHREADS; i++)
        pthread_create(threads + i, &attr, spct_handler, (void *)&(targs));

    sleep(5);
    while (targs.signaled == false)
    {
        write_log(&(targs.args.log));
        sleep(5);
    }

    for (int i = 0; i < NTHREADS; i++)
        pthread_join(*(threads + i), NULL);

    fprintf(stdout, "[Results] (%dh,%dm,%ds)\t%ld packets\t%ld bits (s)\t%ld bits (c)\t%ld bits (t)\n",
            targs.args.log.elapsed_time / 3600, targs.args.log.elapsed_time / 60, targs.args.log.elapsed_time % 60,
            targs.args.log.packets,
            targs.args.log.stored_bytes * 8,
            targs.args.log.captured_bytes * 8,
            targs.args.log.total_bytes * 8);

    /* Close data and exit */
    pcap_close(targs.handle);
    pthread_attr_destroy(&attr);

#ifndef __SIMSTORAGE
    pcap_dump_flush(targs.args.file);
    pcap_dump_close(targs.args.file);
#endif

    psem_destroy(targs.read_mutex);
    psem_destroy(targs.write_mutex);
    psem_destroy(targs.args.log.log_mutex);

    return EXIT_SUCCESS;
}