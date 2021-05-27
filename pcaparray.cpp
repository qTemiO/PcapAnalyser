#include <fstream>
#include "pcaparray.h"
#include "string.h"

#define MAX_CNT 10

pcaparray::pcaparray()
{
    // Инициализация переменных

    PaketArray = 0;

    paket_number = -1;
    minLen = 0;
    maxLen = 0;
    mediumLen = 0;
}

pcaparray::~pcaparray()
{
    // Процедура удаления массива пакетов

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
    // Последовательно выводим аттрибуты заголовка файла пакетов

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
    // Если пытается вывести пакет вне массива пакетов
    if (Number > paket_number)
        return -1;
    // Выводим инфу предыдущего пакета (т.к. считаем с 0)
    return PaketArray[Number-1]->PrintData();
}

void pcaparray::ReadPcapFile(const string FName)
{
    //Открываем файл с переданным именем
    fstream file;
    file.open(FName, ios::in | ios::binary);
    if (!file.is_open())
    {
        cout << "File not open." << endl;
        exit(1);
    }

    //Копируем по-умному название файла в секуэнс
    FileName =  FName;

    //Читаем заголовок файла
    file.read((char*)&FileHeader, sizeof(FileHeader));

    //Собираем статистику по хидерам
    //На предмет наибольшей/наименьшей длинны, средней длинны и количества пакетов вцелом
    while (!file.eof())
    {
        //Ограничим количество передаваемых пакетов
        if (paket_number >= MAX_CNT)
            break;

        //Создаем хидер
        pcap_paket_header pcapHeader;

        //Читаем его
        file.read((char*) &pcapHeader, sizeof(pcapHeader));

        //Перескакиваем указателем на длинну хидера
        file.seekg(pcapHeader.caplen,ios_base::cur);

        //Количество пакетов +1
        paket_number++;

        //Немного статистики
        if (pcapHeader.caplen > maxLen)
            maxLen = pcapHeader.caplen;
        if (pcapHeader.caplen < minLen)
            minLen = pcapHeader.caplen;
        mediumLen += pcapHeader.caplen;

    }

    mediumLen = mediumLen / paket_number;
    int paket_count = 0;

    //Проскочим ненужную служебную информацию о хидере файла
    file.seekg(sizeof(FileHeader), ios_base::beg);
    //Выделим место для всего количества пакетов в 1й массив !!! Мб использовать для инт память? Для экономии
    PaketArray = new PcapPacket*[paket_number];

    while (!file.eof())
    {
        //Помним про ограничение по количеству пакетов
        if (paket_count >= MAX_CNT)
            break;

        //Создаем хидер
        pcap_paket_header pcapHeader;

        //Читаем его
        file.read((char*)&pcapHeader, sizeof(pcapHeader));

        //Объявляем буфер-переменную данных пакета
        unsigned char *paketData = new unsigned char[pcapHeader.caplen];

        //Читаем данные согласно длинне хидера пакета
        file.read((char*)paketData, pcapHeader.caplen);

        //Выделяем память (ещё раз?) под отдельный пакет
        PaketArray[paket_count] = new PcapPacket;

        //Передаем соответствующему пакету его данные
        PaketArray[paket_count]->SetData(pcapHeader, paketData);

        //Повышаем счетчик
        paket_count++;
    }
    file.close();
}

