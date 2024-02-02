#ifndef __SIGHANDLING_H
#define __SIGHANDLING_H

#define _GNU_SOURCE
#include <features.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include "types.h"

/**
 * @brief Fills mask SIGMASK with all signals but SIG_NO.
 */
#define fill_mask_except(sigmask, sig_no) \
        sigfillset(&sigmask);             \
        sigdelset(&sigmask, sig_no)

/**
 * @brief Set signal SIG_NO as the only element of the mask SIGMASK.
 */
#define set_mask(sigmask, sig_no) \
        sigemptyset(&sigmask);    \
        sigaddset(&sigmask, sig_no)

/**
 * Blocks all signals for the current process.
 * 
 * @return On success, 0 is returned.  On failure, -1 is returned.
 */
int block_all_signals();

/**
 * Blocks the given signal.
 *
 * @param signo     Signal number
 * @return On success, 0 is returned. On failure, -1 is returned.
 */
int block_signal(int signo);

/**
 * Unlocks the given signal.
 *
 * @param signo     Signal number
 * @return On success, 0 is returned. On failure, -1 is returned.
 */
int unblock_signal(int signo);

/**
 * @brief Defines a handler function for the given signal
 *
 * @param signo     Signal number
 * @param handler   Function pointer for the signal handler
 * @return On success, 0 is returned. On failure, -1 is returned.
 */
int install_handler(int signo, __sighandler_t handler);

#endif