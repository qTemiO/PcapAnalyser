#ifndef PCAPARRAY_H
#define PCAPARRAY_H

#include "string.h"
#include <pcappacket.h>

struct pcap_file_header {
    unsigned long magic;
    unsigned short version_major;
    unsigned short version_minor;
    int thiszone;	/* gmt to local correction */
    unsigned long sigfigs;	/* accuracy of timestamps */
    unsigned long snaplen;	/* max length saved portion of each pkt */
    unsigned long linktype;	/* data link type (LINKTYPE_*) */
};

class pcaparray
{
    public:
        pcaparray();
        ~pcaparray();

        void ReadPcapFile(string FName);
        void PrintAttribs();
        int PrintPaketData(int Number);

    private:
        string FileName;
        pcap_file_header FileHeader;

        PcapPacket **PaketArray;

        int paket_number;
        unsigned int minLen;
        unsigned int maxLen;
        unsigned int mediumLen;
};


#endif // PCAPARRAY_H
