#include "parser.h"

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    kernel_args *args = (kernel_args *)state->input;

    switch (key)
    {
    case 'p':
        args->percentage = atoi(arg);
        if (args->percentage <= 0 || args->percentage > 100)
        {
            fprintf(stderr, "no\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'r':
        args->runlen = atoi(arg);
        if (args->runlen <= 0)
        {
            fprintf(stderr, "no\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        args->ktype = (kernel_type)atoi(arg);
        if (args->ktype < VANILLA_PACKET_THREAD || args->ktype > COERCIVE_PACKET_WARP)
        {
            fprintf(stderr, "no\n");
            exit(EXIT_FAILURE);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}