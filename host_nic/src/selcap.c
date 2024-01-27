#include "selcap.h"

/**
 * Returns the starting index for the payload for the given packet.
 * Currently works only for TCP/IP packets. 
 * 
 * @param packet Packet to process
 * @return Length of the packet header on supported packet type, 0 on
 * unsupported packet type or error.
 */
int header_len(unsigned char* packet)
{
    ETHeader* eth;
    IPHeader* iph;
    TCPHeader* tcph;
    
    eth = (ETHeader*) packet;
    if (ntohs(eth->ether_type) != ETHERTYPE_IP)
        return 0;

    iph = (IPHeader*) (packet + ETH_HLEN);
    if(IP_HL(iph) < 20 || iph->protocol != IPPROTO_TCP)
        return 0;

    tcph = (TCPHeader*)(packet + ETH_HLEN + IP_HL(iph));

    return ETH_HLEN + IP_HL(iph) + (TCP_OFFSET(tcph) * 4); 
}

void selective_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    HandlerArgs hargs = *(HandlerArgs *)(args);
    int consecutive, total, payload_start;
    unsigned char *payload = NULL;

    /* For now, return if we don't know the header length (this packet is lost) */
    if((payload_start = header_len(packet)) == 0)
        return;
    consecutive = total = 0;

    for (int i = payload_start; i < header->caplen; i++)
    {
        if (payload[i] >= MIN_ASCII && payload[i] <= MAX_ASCII)
        {
            consecutive++;
            total += 100;
            if (consecutive == hargs.threshold)
            {
                // TODO do not cap packet
                return;
            }
        }
        else
            consecutive = 0;
    }
    if (total >= (hargs.percentage * header->caplen))
    {
        // TODO do not cap packet
        return;
    }
    // TODO cap packet
    return;
}

void selective_capping_optimized(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    HandlerArgs hargs = *(HandlerArgs *)(args);
    int consecutive, total, payload_start;
    unsigned char *payload = NULL;

    /* For now, return if we don't know the header length (this packet is lost) */
    if((payload_start = header_len(packet)) == -1)
        return;
    consecutive = total = 0;

    /* Assume that the packet payload is at least threshold bytes long */
    for (int i = payload_start + hargs.threshold-1, j = payload_start + hargs.threshold-1; i < header->caplen; j--)
    {
        if (payload[j] >= MIN_ASCII && payload[j] <= MAX_ASCII)
        {
            consecutive++;
            total += 100;
            if (consecutive == hargs.threshold)
            {
                // TODO do not cap packet
                return;
            }
        }
        else
        {
            consecutive = 0;
            i += hargs.threshold;
            j = i + 1;
        }
    }
    if (total >= (hargs.percentage * header->caplen))
    {
        // TODO do not cap packet
        return;
    }
    // TODO cap packet
    return;
}