#include "selcap.h"

/**
 * Returns the starting index for the payload for the given packet.
 * Currently works for TCP and UDP packets, taking VLAN tags into
 * consideration.
 *
 * @param packet Packet to process.
 * @return Length of the packet header on supported packet type, 0 on
 * unsupported packet type or error.
 */
int header_len(const unsigned char *packet, bpf_u_int32 caplen)
{
    int header_len = ETH_HLEN;
    ETHeader *eth_header;
    IPHeader *ip_header;
    TCPHeader *tcp_header;

    eth_header = (ETHeader *)packet;

    /* Skip over 802.1q tags */
    while (ntohs(eth_header->ether_type) == ETHERTYPE_VLAN)
    {
        eth_header += VLAN_HLEN;
        header_len += VLAN_HLEN;
    }

    /* Not IP, skipping packet... */
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP)
        return ERR_UNSUPPORTED;

    ip_header = (IPHeader *)(packet + header_len);
    header_len += IP_HL(ip_header);

    /* Ill-formed, skipping packet... */
    if (IP_HL(ip_header) < 20 || header_len > caplen)
        return ERR_ILL_FORMED;

    if (ip_header->protocol == IPPROTO_UDP)
        return header_len + UDP_LEN < caplen ? header_len + UDP_LEN : ERR_ILL_FORMED;

    if (ip_header->protocol == IPPROTO_TCP)
    {
        tcp_header = (TCPHeader *)(packet + header_len);
        header_len += (TCP_OFFSET(tcp_header) * 4);
        return header_len < caplen ? header_len : ERR_ILL_FORMED;
    }

    return ERR_UNSUPPORTED;
}

void selective_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    HandlerArgs h_args = *(HandlerArgs *)(args);
    int consecutive, total, payload_start;

    /* Skip the packet on error */
    if ((payload_start = header_len(packet, header->caplen)) < 0)
        return;
    consecutive = total = 0;

    for (int i = payload_start; i < header->caplen; i++)
    {
        if (packet[i] >= MIN_ASCII && packet[i] <= MAX_ASCII)
        {
            consecutive++;
            total += 100;
            if (consecutive == h_args.threshold)
            {
                printf("Do not cap.\n");
                return;
            }
        }
        else
            consecutive = 0;
    }

    if (total >= (h_args.percentage * header->caplen))
    {
        printf("Do not cap. Total ASCII:%.2lf\n", (total * 1.0 / header->caplen));
        return;
    }

    printf("Cap. Total ASCII:%.2lf\n", (total * 1.0 / header->caplen));
}

void selective_capping_optimized(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    HandlerArgs h_args = *(HandlerArgs *)(args);
    int consecutive, total, payload_start;

    /* Skip the packet on error */
    if ((payload_start = header_len(packet, header->caplen)) < 0)
        return;
    
    /* Skip if payload cannot reach threshold */
    if(payload_start + h_args.threshold - 1 > header->caplen)
        return;
    
    consecutive = total = 0;
    for (int i = payload_start + h_args.threshold - 1; i >= payload_start && i < header->caplen; i--)
    {
        if (packet[i] >= MIN_ASCII && packet[i] <= MAX_ASCII)
        {
            consecutive++;
            total += 100;
            if (consecutive == h_args.threshold)
            {
                printf("Do not cap.\n");
                return;
            }
        }
        else
        {
            consecutive = 0;
            i += h_args.threshold + 1;
        }
    }

    if (total >= (h_args.percentage * header->caplen))
    {
        printf("Do not cap. Total ASCII:%.2lf\n", (total * 1.0 / header->caplen));
        return;
    }

    printf("Cap. Total ASCII:%.2lf\n", (total * 1.0 / header->caplen));
}