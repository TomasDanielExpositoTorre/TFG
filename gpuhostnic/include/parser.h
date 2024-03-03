#ifndef SPC_PARSER_H
#define SPC_PARSER_H

#include <stdlib.h>
#include <argp.h>
#include "cuda_headers.h"

error_t parse_opt(int key, char *arg, struct argp_state *state);

#endif