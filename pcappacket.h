#ifndef PCAPPACKET_H
#define PCAPPACKET_H
using namespace std;
#include <iostream>

struct timeval {
  long tv_sec;
  long tv_usec;
};

struct pcap_paket_header {
    timeval ts;	/* time stamp */
    unsigned long caplen;	/* length of portion present */
    unsigned long len;	/* length this packet (off wire) */
};


class PcapPacket
{
    public:
        PcapPacket();
        ~PcapPacket();
        void SetData(pcap_paket_header header, unsigned char *data);
        int PrintData();


        pcap_paket_header paket_header;
        unsigned char* paket_data;



};

#endif // PCAPPACKET_H
