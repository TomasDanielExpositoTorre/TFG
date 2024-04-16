#include "headers.h"

/**
 * Returns the starting index for the payload for the given packet.
 * Currently works for TCP and UDP packets, taking VLAN tags into
 * consideration.
 *
 * @param packet Packet to process.
 * @return Length of the packet header on supported packet type, negative
 * value representing an error type otherwise.
 */
int header_len(const unsigned char *packet, bpf_u_int32 caplen)
{
    struct eth_header *eth;
    struct ip_header *iph;
    struct tcp_header *tcph;
    int hlen = 0;

    /* Skip over 802.1q tags */
    while (ntohs((unsigned short)*(packet + 12 + hlen)) == ETHERTYPE_VLAN)
        hlen += VLAN_HLEN;

    eth = (struct eth_header *)(packet + hlen);
    hlen += ETH_HLEN;
    /* Not IP, skipping packet... */
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return ERR_UNSUPPORTED;

    iph = (struct ip_header *)(packet + hlen);
    hlen += IP_HL(iph);

    /* Ill-formed, skipping packet... */
    if (IP_HL(iph) < 20 || hlen > caplen)
        return ERR_ILLFORMED;

    if (iph->protocol == IPPROTO_UDP)
        return hlen + UDP_LEN < caplen ? hlen + UDP_LEN : ERR_ILLFORMED;

    if (iph->protocol == IPPROTO_TCP)
    {
        tcph = (struct tcp_header *)(packet + hlen);
        hlen += (TCP_OFFSET(tcph) * 4);
        return hlen < caplen ? hlen : ERR_ILLFORMED;
    }

    return ERR_UNSUPPORTED;
}

void write_log(struct logging_info *log)
{
    int hours, minutes;
    float sbps, cbps, tbps, pps;
    char su, cu, tu;
    log->elapsed_time += 5;
    minutes = log->elapsed_time / 60;
    hours = minutes / 60;

    pthread_mutex_lock(&(log->log_mutex));
    pps = (float)(log->packets) / log->elapsed_time;
    sbps = (log->stored_bytes * 8.0) / log->elapsed_time;
    cbps = (log->captured_bytes * 8.0) / log->elapsed_time;
    tbps = (log->total_bytes * 8.0) / log->elapsed_time;
    pthread_mutex_unlock(&(log->log_mutex));

    su = (sbps > GIGABIT) ? 'G' : (sbps > MEGABIT) ? 'M'
                                                   : 'K';
    cu = (cbps > GIGABIT) ? 'G' : (cbps > MEGABIT) ? 'M'
                                                   : 'K';
    tu = (tbps > GIGABIT) ? 'G' : (tbps > MEGABIT) ? 'M'
                                                   : 'K';

    sbps = (sbps > GIGABIT) ? (sbps / GIGABIT) : (sbps > MEGABIT) ? (sbps / MEGABIT)
                                                                  : (sbps / KILOBIT);
    cbps = (cbps > GIGABIT) ? (cbps / GIGABIT) : (cbps > MEGABIT) ? (cbps / MEGABIT)
                                                                  : (cbps / KILOBIT);
    tbps = (tbps > GIGABIT) ? (tbps / GIGABIT) : (tbps > MEGABIT) ? (tbps / MEGABIT)
                                                                  : (tbps / KILOBIT);

    fprintf(stdout, "[Logging] (%02d:%02d:%02d)    %.2f pps\t%.2f %cbps (stored)\t%.2f %cbps (captured)\t%.2f %cbps (total)\n",
            hours, minutes % 60, log->elapsed_time % 60, pps, sbps, su, cbps, cu, tbps, tu);
}

// #ifndef __OPTIMIZED
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
// #else
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
// #endif

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
        // pcap_dump((unsigned char *)_args->file, header, packet);
    }
    else
    {
        log_update((&(_args->log)), slice, header->caplen, header->len);
        struct pcap_pkthdr *h = (struct pcap_pkthdr *)header;
        h->caplen = slice;
        fwrite_unlocked(header, sizeof(struct pcap_pkthdr), 1, _args->file);
        fwrite_unlocked(packet, header->caplen, 1, _args->file);
        // pcap_dump((unsigned char *)_args->file, h, packet);
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

void *spct_handler(void *args)
{
    struct thread_arguments *targs = (struct thread_arguments *)args;
    struct arguments _args = targs->args;
    const unsigned char *packet;
    struct pcap_pkthdr *header;
    int slice;

    while (targs->signaled == false)
    {
        psem_down(targs->read_mutex);
        if (pcap_next_ex(targs->handle, &header, &packet) < 0)
        {
            targs->signaled = true;
            psem_up(targs->read_mutex);
            return NULL;
        }
        psem_up(targs->read_mutex);

#ifndef __OPTIMIZED
        slice = selective_capping(_args, header, packet);
#else
        slice = optimized_capping(_args, header, packet);
#endif

#ifndef __SIMSTORAGE
        if (slice == NO_CAPPING)
        {
            log_update((&(targs->args.log)), header->caplen, header->caplen, header->len);
            psem_down(targs->write_mutex);
            pcap_dump((unsigned char *)_args.file, header, packet);
            psem_up(targs->write_mutex);
        }
        else
        {
            log_update((&(targs->args.log)), slice, header->caplen, header->len);
            psem_down(targs->write_mutex);
            header->caplen = slice;
            pcap_dump((unsigned char *)_args.file, header, packet);
            psem_up(targs->write_mutex);
        }
#else
        if (slice == NO_CAPPING)
        {
            log_update((&(targs->args.log)), header->caplen, header->caplen, header->len);
        }
        else
        {
            log_update((&(targs->args.log)), slice, header->caplen, header->len);
        }
#endif
    }
    return NULL;
}