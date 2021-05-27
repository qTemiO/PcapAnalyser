#include <fstream>
#include "pcaparray.h"
#include "string.h"

#define MAX_CNT 10

pcaparray::pcaparray()
{
    // ������������� ����������

    PaketArray = 0;

    paket_number = -1;
    minLen = 0;
    maxLen = 0;
    mediumLen = 0;
}

pcaparray::~pcaparray()
{
    // ��������� �������� ������� �������

    if (paket_number > 0)
    {
        for(int i=0; i<paket_number; i++)
        {
            delete PaketArray[i];
        }
        delete []PaketArray;
    }
}


void pcaparray::PrintAttribs()
{
    // ��������������� ������� ��������� ��������� ����� �������

    cout << "Attributes for packet sequence from file " << FileName << ":" << endl;

    cout << dec;
    cout << "Link type: "  << FileHeader.linktype << endl;
    cout << "Number: "  << paket_number << endl;
    cout << "Min Length: "  << minLen << endl;
    cout << "Max Length: "  << maxLen << endl;
    cout << "Middle Length: "  << mediumLen << endl;
    cout << "Magic : " << FileHeader.magic << endl;
}

int pcaparray::PrintPaketData(int Number)
{
    // ���� �������� ������� ����� ��� ������� �������
    if (Number > paket_number)
        return -1;
    // ������� ���� ����������� ������ (�.�. ������� � 0)
    return PaketArray[Number-1]->PrintData();
}

void pcaparray::ReadPcapFile(const string FName)
{
    //��������� ���� � ���������� ������
    fstream file;
    file.open(FName, ios::in | ios::binary);
    if (!file.is_open())
    {
        cout << "File not open." << endl;
        exit(1);
    }

    //�������� ��-������ �������� ����� � �������
    FileName =  FName;

    //������ ��������� �����
    file.read((char*)&FileHeader, sizeof(FileHeader));

    //�������� ���������� �� �������
    //�� ������� ����������/���������� ������, ������� ������ � ���������� ������� ������
    while (!file.eof())
    {
        //��������� ���������� ������������ �������
        if (paket_number >= MAX_CNT)
            break;

        //������� �����
        pcap_paket_header pcapHeader;

        //������ ���
        file.read((char*) &pcapHeader, sizeof(pcapHeader));

        //������������� ���������� �� ������ ������
        file.seekg(pcapHeader.caplen,ios_base::cur);

        //���������� ������� +1
        paket_number++;

        //������� ����������
        if (pcapHeader.caplen > maxLen)
            maxLen = pcapHeader.caplen;
        if (pcapHeader.caplen < minLen)
            minLen = pcapHeader.caplen;
        mediumLen += pcapHeader.caplen;

    }

    mediumLen = mediumLen / paket_number;
    int paket_count = 0;

    //��������� �������� ��������� ���������� � ������ �����
    file.seekg(sizeof(FileHeader), ios_base::beg);
    //������� ����� ��� ����� ���������� ������� � 1� ������ !!! �� ������������ ��� ��� ������? ��� ��������
    PaketArray = new PcapPacket*[paket_number];

    while (!file.eof())
    {
        //������ ��� ����������� �� ���������� �������
        if (paket_count >= MAX_CNT)
            break;

        //������� �����
        pcap_paket_header pcapHeader;

        //������ ���
        file.read((char*)&pcapHeader, sizeof(pcapHeader));

        //��������� �����-���������� ������ ������
        unsigned char *paketData = new unsigned char[pcapHeader.caplen];

        //������ ������ �������� ������ ������ ������
        file.read((char*)paketData, pcapHeader.caplen);

        //�������� ������ (��� ���?) ��� ��������� �����
        PaketArray[paket_count] = new PcapPacket;

        //�������� ���������������� ������ ��� ������
        PaketArray[paket_count]->SetData(pcapHeader, paketData);

        //�������� �������
        paket_count++;
    }
    file.close();
}

