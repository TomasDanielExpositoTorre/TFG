#ifndef __UTILS__H__
#define __UTILS__H__

#include "headers.h"

void mastercore(std::vector<CommunicationRing *> &ring, struct arguments args);

/**
 * Parsing function for received user arguments.
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

/**
 * Parsing function for received user arguments.
 */
void check_args(struct arguments args);
#endif