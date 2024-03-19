#include "headers.h"

error_t parse_opt(int key, char *arg, struct argp_state *state)
{
    struct arguments *args = (struct arguments *)state->input;

    switch (key)
    {
    case 'p':
        args->ascii_percentage = atoi(arg);
        if (args->ascii_percentage <= 0 || args->ascii_percentage > 100)
        {
            fprintf(stderr, "Incorrect ASCII percentage. Value must be from 1 to 100\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'r':
        args->ascii_runlen = atoi(arg);
        if (args->ascii_runlen <= 0 || args->ascii_runlen > RTE_ETHER_MAX_LEN)
        {
            fprintf(stderr, "Incorrect ASCII runlen. Value must be a postive number\n");
            exit(EXIT_FAILURE);
        }
        break;
    case 'k':
        args->kernel = atoi(arg);
        if (args->kernel < VANILLA_CAPPING_THREAD || args->kernel > COERCIVE_CAPPING_WARP)
        {
            fprintf(stderr, "Incorrect kernel type. Value must be from %d to %d\n", VANILLA_CAPPING_THREAD, COERCIVE_CAPPING_WARP);
            exit(EXIT_FAILURE);
        }
        break;
    case 'o':
        args->output = arg;
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}