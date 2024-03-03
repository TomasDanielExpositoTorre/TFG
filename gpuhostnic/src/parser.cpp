#include "parser.h"

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    pipeline *p = (pipeline *)state->input;

    switch (key)
    {
    case 'p':
        p->percentage = atoi(arg);
        if (p->percentage <= 0 || p->percentage > 100)
        {
            fprintf(stderr, "no\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'r':
        p->runlen = atoi(arg);
        if (p->runlen <= 0)
        {
            fprintf(stderr, "no\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        p->kernel = atoi(arg);
        if (p->kernel < VANILLA_PACKET_THREAD || p->kernel > COERCIVE_PACKET_WARP)
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