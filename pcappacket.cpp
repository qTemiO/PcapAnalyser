#include "pcappacket.h"

PcapPacket::PcapPacket()
{
    paket_data= 0;
}

PcapPacket::~PcapPacket()
{
    // ���� ���� �� ������, ������� � ����
    if(paket_data != 0)
        delete []paket_data;
}

void PcapPacket::SetData(pcap_paket_header header, unsigned char *data)
{
    paket_header = header;
    paket_data = data;
}

int PcapPacket::PrintData()
{
    // ���� ���� ������ ������ �� ������
    if(paket_data == 0)
    {
        cout << "No Data here" << endl;
        return -1;
    }
    //������� ��������� ���������� - ������ ������
    cout << "Captured lenght: " << paket_header.caplen << endl;
    cout << hex << uppercase;

    //��������� ���� ������ �� 16 �����
    int Rows = (paket_header.caplen/16) + 1;
    int currentByte = 0;

    for(int i = 0; i < Rows; i++)
    {
        for (int j = 0; j < 16; j++)
        {
            unsigned int this_byte = paket_data[currentByte];

            if(this_byte < 0x10) //���� ������ ���
                cout << "0";
            cout << this_byte << " ";

            currentByte++;
            if (currentByte == paket_header.caplen) //���� ����� �� ����� - ����������� � �������
                break;
        }
        cout << endl;
    }
    return 0;
}
