#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include "selcap.h"

const char *argp_program_version = "HostNic 1.0";
const char *argp_program_bug_address = "<tomas.exposito@estudiante.uam.es>";

static struct argp_option options[] = {
    {"if", 'i', "name", 0, "Interface used to capture packets."},
    {"percentage", 'p', "int", 0, "Percentage of ASCII required per packet."},
    {"threshold", 't', "int", 0, "Consecutive ASCII threshold per packet."},
    {0}};

struct arguments
{
    SelectiveCapperArguments sc;
    char* interface;
};

static error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = state->input;

    switch (key)
    {
    case 'i':
        args->interface = arg;
        break;
    case 'p':
        args->sc.percentage = (uint8_t)atoi(arg);
        break;
    case 't':
        args->sc.threshold = (uint8_t)atoi(arg);
        break;
    case ARGP_KEY_END:
        if (args->sc.percentage <= 0 || args->sc.percentage > 100)
        {
            fprintf(stdout, "Given percentage must be a value between 1 and 100.\n");
            exit(EXIT_FAILURE);
        }
        if (args->sc.threshold == 0)
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

int main(int argc, char** argv)
{
    struct arguments args;
    pcap_t* handle;
    char error_buff[PCAP_ERRBUF_SIZE];
    
    args.sc.percentage = 45;
    args.sc.threshold = 15;
    args.interface = NULL;
    argp_parse(&argp, argc, argv, 0, 0, &args);

    if (pcap_init(PCAP_CHAR_ENC_UTF_8, error_buff) == PCAP_ERROR)
    {
        fprintf(stderr, "%s\n", error_buff);
        return EXIT_FAILURE;
    }

    handle = pcap_open_live(args.interface, BUFSIZ, 1, 1000, error_buff);
    
    if (handle == NULL)
    {
        fprintf(stderr, "Couldn't open device %s\n", error_buff);
        return EXIT_FAILURE;
    }

    pcap_loop(handle, -1, selective_capping, (unsigned char*)&(args.sc));
    pcap_close(handle);
    return EXIT_SUCCESS;
}