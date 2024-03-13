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
    log->elapsed_time += 5;
    minutes = log->elapsed_time / 60;
    hours = minutes / 60;

    pthread_mutex_lock(&(log->log_mutex));
    fprintf(stdout, "[Logging] (%dh,%dm,%ds)\t%.2f pps\t%.2f bps (s)\t%.2f bps (c)\t%.2f bps (t)\n",
            hours, minutes % 60, log->elapsed_time % 60,
            (float)(log->packets) / log->elapsed_time,
            (log->stored_bytes * 8.0) / log->elapsed_time,
            (log->captured_bytes * 8.0) / log->elapsed_time,
            (log->total_bytes * 8.0) / log->elapsed_time);
    pthread_mutex_unlock(&(log->log_mutex));
}

#ifndef __OPTIMIZED
int vanilla_capping(struct arguments args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    int runlen = 0, total = 0, hlen;

    /* Skip the packet on error */
    if ((hlen = header_len(packet, header->caplen)) < 0)
        return hlen;

    for (int i = hlen; i < header->caplen; i++)
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

    return hlen;
}
#else
int optimized_capping(struct arguments args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    int runlen = 0, total = 0, seen = 0, hlen;

    /* Skip the packet on error */
    if ((hlen = header_len(packet, header->caplen)) < 0)
        return hlen;

    /* Cap if payload cannot reach threshold */
    if (hlen + args.ascii_runlen - 1 > header->caplen)
        return hlen;

    for (int i = hlen + args.ascii_runlen - 1; i >= hlen && i < header->caplen; i--, seen++)
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

    return hlen;
}
#endif

void spc_handler(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    struct arguments *_args = (struct arguments *)(args);

#ifndef __OPTIMIZED
    int slice = vanilla_capping(*_args, header, packet);
#else
    int slice = optimized_capping(*_args, header, packet);
#endif

#ifndef __SIMSTORAGE
    if (slice == NO_CAPPING)
    {
        log_update((&(_args->log)), header->caplen, header->caplen, header->len);
        pcap_dump((unsigned char *)_args->file, header, packet);
    }
    else if (slice > NO_CAPPING)
    {
        log_update((&(_args->log)), slice, header->caplen, header->len);
        struct pcap_pkthdr *h = (struct pcap_pkthdr *)header;
        h->caplen = slice;
        pcap_dump((unsigned char *)_args->file, h, packet);
    }
#else
    if (slice == NO_CAPPING)
    {
        log_update((&(_args->log)), header->caplen, header->caplen, header->len);
    }
    else if (slice > NO_CAPPING)
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
    struct pcap_pkthdr header;
    int slice;

    while (targs->signaled == false)
    {
        psem_down(targs->read_mutex);
        packet = pcap_next(targs->handle, &header);
        psem_up(targs->read_mutex);

#ifndef __OPTIMIZED
        slice = vanilla_capping(_args, &header, packet);
#else
        slice = optimized_capping(_args, &header, packet);
#endif

#ifndef __SIMSTORAGE
        if (slice == NO_CAPPING)
        {
            log_update((&(targs->args.log)), header.caplen, header.caplen, header.len);
            psem_down(targs->write_mutex);
            pcap_dump((unsigned char *)_args.file, &header, packet);
            psem_up(targs->write_mutex);
        }
        else if (slice > NO_CAPPING)
        {
            log_update((&(targs->args.log)), slice, header.caplen, header.len);
            psem_down(targs->write_mutex);
            header.caplen = slice;
            pcap_dump((unsigned char *)_args.file, &header, packet);
            psem_up(targs->write_mutex);
        }
#else
        if (slice == NO_CAPPING)
        {
            log_update((&(targs->args.log)), header.caplen, header.caplen, header.len);
        }
        else if (slice > NO_CAPPING)
        {
            log_update((&(targs->args.log)), slice, header.caplen, header.len);
        }
    }
#endif
        return NULL;
    }