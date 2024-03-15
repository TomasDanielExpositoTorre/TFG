#ifndef SPC_PARSER_H
#define SPC_PARSER_H

#include "headers.h"

/* =====================    RX/TX  Cores    ===================== */

/**
 * TODO document this function
 */
int rx_core(void *args);

/**
 * TODO document this function
 */
int tx_core(void *args);

/* =====================  Other  Functions  ===================== */

/**
 * TODO document this function
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

#endif