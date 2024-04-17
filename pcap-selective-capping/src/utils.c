#include "headers.h"

void write_log(struct logging_info *log)
{
    int hours, minutes;
    float sbps, cbps, tbps, pps;
    char su, cu, tu;
    log->elapsed_time += 5;
    minutes = log->elapsed_time / 60;
    hours = minutes / 60;

    pthread_mutex_lock(&(log->log_mutex));
    pps = log->packets;
    sbps = log->stored_bytes;
    cbps = log->captured_bytes;
    tbps = log->total_bytes;
    pthread_mutex_unlock(&(log->log_mutex));

    pps /= log->elapsed_time;
    sbps = (sbps * 8) / log->elapsed_time;
    cbps = (cbps * 8) / log->elapsed_time;
    tbps = (tbps * 8) / log->elapsed_time;

    printf("%.2f %.2f %.2f\n", sbps, cbps, tbps);
    speed_format(sbps, su);
    speed_format(cbps, cu);
    speed_format(tbps, tu);
    printf("%.2f %.2f %.2f\n", sbps, cbps, tbps);
    
    fprintf(stdout, "[%02d:%02d:%02d]    %.2f pps\t%.2f %cbps (stored)\t%.2f %cbps (captured)\t%.2f %cbps (total)\n",
            hours, minutes % 60, log->elapsed_time % 60, pps, sbps, su, cbps, cu, tbps, tu);
}

#ifndef __OPTIMIZED
int selective_capping(struct arguments args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    int runlen = 0, total = 0;

    for (int i = MIN_HLEN; i < header->caplen; i++)
    {
        if (packet[i] >= MIN_ASCII && packet[i] <= MAX_ASCII)
        {
            runlen++;
            total += 100;
            if (runlen == args.ascii_runlen)
                return NO_CAPPING;
        }
        else
            runlen = 0;
    }

    if (total >= (args.ascii_percentage * header->caplen))
        return NO_CAPPING;

    return (MAX_HLEN > header->caplen) ? header->caplen : MAX_HLEN;
}
#else
int optimized_capping(struct arguments args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    int runlen = 0, total = 0, seen = 0;

    for (int i = MIN_HLEN + args.ascii_runlen - 1; i >= MIN_HLEN && i < header->caplen; i--, seen++)
    {
        if (packet[i] >= MIN_ASCII && packet[i] <= MAX_ASCII)
        {
            runlen++;
            total += 100;
            if (runlen == args.ascii_runlen)
                return NO_CAPPING;
        }
        else
        {
            runlen = 0;
            i += args.ascii_runlen + 1;
        }
    }

    if (total >= (args.ascii_percentage * seen))
        return NO_CAPPING;

    return (MAX_HLEN > header->caplen) ? header->caplen : MAX_HLEN;
}
#endif

void spc_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct arguments *_args = (struct arguments *)(args);
#ifndef __OPTIMIZED
    int slice = selective_capping(*_args, header, packet);
#else
    int slice = optimized_capping(*_args, header, packet);
#endif

#ifndef __SIMSTORAGE
    if (slice == NO_CAPPING)
    {
        log_update((&(_args->log)), header->caplen, header->caplen, header->len);
        fwrite_unlocked(header, sizeof(struct pcap_pkthdr), 1, _args->file);
        fwrite_unlocked(packet, header->caplen, 1, _args->file);
    }
    else
    {
        log_update((&(_args->log)), slice, header->caplen, header->len);
        struct pcap_pkthdr *h = (struct pcap_pkthdr *)header;
        h->caplen = slice;
        fwrite_unlocked(header, sizeof(struct pcap_pkthdr), 1, _args->file);
        fwrite_unlocked(packet, header->caplen, 1, _args->file);
    }

#else
    if (slice == NO_CAPPING)
    {
        log_update((&(_args->log)), header->caplen, header->caplen, header->len);
    }
    else
    {
        log_update((&(_args->log)), slice, header->caplen, header->len);
    }
#endif
}
