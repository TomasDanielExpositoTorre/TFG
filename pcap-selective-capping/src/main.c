#define _GNU_SOURCE
#include "headers.h"

const char *argp_program_version = "HostNic Mono 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"interface", 'i', "name", 0, "Interface used to capture packets."},
    {"output", 'o', "path", 0, "File where captured packets will be dumped."},
    {"input", 'd', "path", 0, "File to read packets from."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = state->input;

    switch (key)
    {
    case 'i':
        args->interface = arg;
        break;
    case 'o':
        args->output = arg;
        break;
    case 'd':
        args->input = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = {options, parse_opt, 0, NULL};
static pcap_t *handle;
static volatile int signaled = false;

void sighandler(int signal)
{
    signaled = true;
    pcap_breakloop(handle);
    printf("\nSIGNAL received, stopping packet capture...\n");
}

void *logging_thread(void *args)
{
    struct logging_info *log = (struct logging_info *)args;
    sleep(5);

    while (signaled == false)
    {
        write_log(log);
        sleep(5);
    }

    return NULL;
}

int main(int argc, char **argv)
{
    struct arguments args = {
        .ascii_percentage = 45,
        .ascii_runlen = 15,
        .interface = "enp51s0f0np0",
        .input = NULL,
        .output = NULL,
        .log = {
            .packets = 0,
            .stored_bytes = 0,
            .captured_bytes = 0,
        },
    };
    struct pcap_file_header pcap_header = {
        .magic = PCAP_USEC,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = SNAPLEN_SIZE,
        .linktype = DLT_EN10MB,
    };
    pthread_attr_t attr;
    pthread_t logger;
    sigset_t thread_mask;
    char error_buff[PCAP_ERRBUF_SIZE];

    /* Block SIGINT for all threads except master */
    set_mask(thread_mask, SIGINT);
    signal(SIGINT, sighandler);

    if (pthread_attr_init(&attr) ||
        pthread_attr_setsigmask_np(&attr, &thread_mask) ||
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED))
    {
        fprintf(stderr, "[Error:Threads] Could not create logging thread mask.\n");
        return EXIT_FAILURE;
    }

    psem_init(args.log.log_mutex);
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }

    /* Initialize packet capture handle and file */
    if (args.input == NULL)
        handle = pcap_open_live(args.interface, SNAPLEN_SIZE, 1, TO_MS_VAL, error_buff);
    else
        handle = pcap_open_offline(args.input, error_buff);

    if (handle == NULL)
    {
        fprintf(stderr, "[Error:Interface] Couldn't open %s\n", error_buff);
        return EXIT_FAILURE;
    }
    if (pcap_datalink(handle) != DLT_EN10MB)
    {
        fprintf(stderr, "[Error:Interface] %s doesn't provide Ethernet headers\n", args.interface);
        pcap_close(handle);
        return EXIT_FAILURE;
    }

#ifndef __SIMSTORAGE
    if (args.output == NULL)
    {
        fprintf(stderr, "[Error:File] Please provide a file path to dump captured packets\n");
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    args.file = fopen(args.output, "wb");
    fwrite_unlocked(&pcap_header, sizeof(struct pcap_file_header), 1, args.file);
#endif

    /*
        Parent - capture packets
        Child - log capture statistics
    */
    pthread_create(&logger, &attr, logging_thread, (void *)&(args.log));
    pcap_loop(handle, -1, spc_handler, (unsigned char *)&(args));

    /* Close data and exit */
    fprintf(stdout, "[Results] (%dh,%dm,%ds)\t%ld packets\t%ld bits (s)\t%ld bits (c)\t%ld bits (t)\n",
            args.log.elapsed_time / 3600, args.log.elapsed_time / 60, args.log.elapsed_time % 60,
            args.log.packets,
            args.log.stored_bytes * 8,
            args.log.captured_bytes * 8,
            args.log.total_bytes * 8);
    
    pcap_close(handle);
    pthread_attr_destroy(&attr);

#ifndef __SIMSTORAGE
    pcap_dump_flush(args.file);
    pcap_dump_close(args.file);
#endif

    psem_destroy(args.log.log_mutex);

    return EXIT_SUCCESS;
}