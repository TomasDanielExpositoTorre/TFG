#include "selcap.h"
#include "sighandling.h"
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

const char *argp_program_version = "HostNic Mono 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"if", 'i', "name", 0, "Interface used to capture packets."},
    {"percentage", 'p', "int", 0, "Percentage of total ASCII required per packet."},
    {"threshold", 't', "int", 0, "Consecutive ASCII required per packet."},
    {0}};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    HandlerArgs *args = state->input;

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

void sighandler(int signal)
{
    pcap_breakloop(handle);
    printf("\nSIGNAL received, stopping packet capture...\n");
}

int main(int argc, char **argv)
{
    HandlerArgs args;
    char error_buff[PCAP_ERRBUF_SIZE];

    if (block_signal(SIGINT) | install_handler(SIGINT, sighandler) | unblock_signal(SIGINT))
    {
        perror("sigaction");
        return EXIT_FAILURE;
    }

    args.percentage = 45;
    args.threshold = 15;
    args.interface = NULL;
    argp_parse(&argp, argc, argv, 0, 0, &args);

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
    pcap_loop(handle, -1, optimized_capping, (unsigned char *)&(args));
    
    pcap_close(handle);
    pcap_dump_flush(args.file);
    pcap_dump_close(args.file);
    return EXIT_SUCCESS;
}