#ifndef __UTILS__H__
#define __UTILS__H__

#include "headers.h"

/**
 * Parsing function for received user arguments.
 */
error_t parse_opt(int key, char *arg, struct argp_state *state);

/**
 * Validator function for received user arguments.
 * 
 * @param args: User arguments. 
 */
void check_args(struct arguments args);

/**
 * Prints statistics every five seconds while the program is running,
 * then prints final statistics after SIGINT is received.
 * 
 * @param ring: Communication ring vector.
 * @param args: User arguments. 
*/
void mastercore(std::vector<CommunicationRing *> &ring, struct arguments args);
#endif