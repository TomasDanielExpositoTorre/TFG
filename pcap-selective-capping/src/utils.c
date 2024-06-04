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

    speed_format(sbps, su);
    speed_format(cbps, cu);
    speed_format(tbps, tu);

    fprintf(stdout, "[%02d:%02d:%02d]    %.2f pps\t%.2f %cbps (stored)\t%.2f %cbps (captured)\t%.2f %cbps (total)\n",
            hours, minutes % 60, log->elapsed_time % 60, pps, sbps, su, cbps, cu, tbps, tu);
}

void callback(unsigned char *uargs, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct arguments *args = (struct arguments *)(uargs);
#ifndef __OPTIMIZED
    int runlen, total, caplen = header->caplen;
    int i;

    /* Skip processing for small packets - should be filtered via hardware */
    if (MAX_HLEN >= caplen)
        goto store_packet;

    total = 0;
    runlen = 0;

    for (i = MIN_HLEN; i < header->caplen; i++)
    {
        if (packet[i] >= MIN_ASCII && packet[i] <= MAX_ASCII)
        {
            runlen++;
            total += 100;
            if (runlen == args->ascii_runlen)
                goto store_packet; /* Do not cap */
        }
        else
            runlen = 0;
    }

    if (total >= (args->ascii_percentage * (header->caplen - MIN_HLEN)))
        goto store_packet; /* Do not cap */
#else
    int total, seen, caplen = header->caplen;
    int i, j;
    
    /* Skip processing for small packets - should be filtered via hardware */
    if (MAX_HLEN >= caplen)
        goto store_packet;

    total = 0;
    seen = 0;

    for (i = MIN_HLEN + args->ascii_runlen - 1; i < header->caplen; i += args->ascii_runlen, seen++)
    {
        if (packet[i] >= MIN_ASCII && packet[i] <= MAX_ASCII) /* Start of run found, iterate backwards */
        {
            total += 100;
            for (j = i - 1; j > i - args->ascii_runlen; j--)
            {
                if (packet[j] >= MIN_ASCII && packet[j] <= MAX_ASCII)
                    total += 100;
                else
                {
                    i = j;
                    goto end_loop; /* Insufficient run size, skip L bytes */
                }
            }
            goto store_packet; /* Loop finished, so a run was found: Do not cap */
        end_loop:;
        }
    }

    if (total >= (args->ascii_percentage * seen))
        goto store_packet; /* Do not cap */
#endif
    caplen = MAX_HLEN; /* Cap packet */

store_packet:
    log_update((&(args->log)), caplen, header->caplen, header->len);
#ifndef __SIMSTORAGE
    fwrite_unlocked(header, sizeof(struct pcap_pkthdr), 1, args->file);
    fwrite_unlocked(packet, caplen, 1, args->file);
#endif
}
