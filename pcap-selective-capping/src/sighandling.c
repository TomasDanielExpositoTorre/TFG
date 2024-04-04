#include "sighandling.h"

int block_all_signals()
{
    sigset_t new;

    if (sigfillset(&new) < 0)
        return ERROR;

    return (sigprocmask(SIG_BLOCK, &new, NULL) == 0) ? OK : ERROR;
}

int unblock_signal(int signo)
{
    sigset_t new;
    int retval = 0;

    retval += sigemptyset(&new);
    retval += sigaddset(&new, signo);

    if (retval < 0)
        return ERROR;

    return (sigprocmask(SIG_UNBLOCK, &new, NULL) == 0) ? OK : ERROR;
}

int block_signal(int signo)
{
    sigset_t new;
    int retval = 0;

    retval += sigemptyset(&new);
    retval += sigaddset(&new, signo);

    if (retval < 0)
        return ERROR;

    return (sigprocmask(SIG_BLOCK, &new, NULL) == 0) ? OK : ERROR;
}

int install_handler(int signo, __sighandler_t handler)
{
    struct sigaction config;

    config.sa_handler = handler;
    config.sa_flags = 0;

    if (sigemptyset(&config.sa_mask) < 0)
        return ERROR;

    return (sigaction(signo, &config, NULL) == 0) ? OK : ERROR;
}