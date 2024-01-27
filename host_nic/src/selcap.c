#include "selcap.h"

void selective_capping(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    SelectiveCapperArguments sc = *(SelectiveCapperArguments *)(args);
    int consecutive = 0, total = 0;
    unsigned char *payload = NULL;
    // TODO remove headers from packet
    // TODO modify caplen condition to only take payload size into account

    for (int i = 0; i < header->caplen; i++)
    {
        if (payload[i] >= MIN_ASCII && payload[i] <= MAX_ASCII)
        {
            consecutive++;
            total += 100;
            if (consecutive == sc.threshold)
            {
                // TODO do not cap packet
                return;
            }
        }
        else
            consecutive = 0;
    }
    if (total >= sc.percentage * header->caplen)
    {
        // TODO do not cap packet
        return;
    }
    // TODO cap packet
    return;
}

void selective_capping_optimized(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    SelectiveCapperArguments sc = *(SelectiveCapperArguments *)(args);
    int consecutive = 0, total = 0;
    unsigned char *payload = NULL;
    // TODO remove headers from packet

    /* Assume that the packet payload is at least threshold bytes long */
    for (int i = sc.threshold-1, j = sc.threshold-1; i < header->caplen; j--)
    {
        if (payload[j] >= MIN_ASCII && payload[j] <= MAX_ASCII)
        {
            consecutive++;
            total += 100;
            if (consecutive == sc.threshold)
            {
                // TODO do not cap packet
                return;
            }
        }
        else
        {
            consecutive = 0;
            i += sc.threshold;
            j = i + 1;
        }
    }
    if (total >= sc.percentage * header->caplen)
    {
        // TODO do not cap packet
        return;
    }
    // TODO cap packet
    return;
}