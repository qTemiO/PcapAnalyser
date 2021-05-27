#include <iostream>
#include<pcappacket.h>
#include "pcaparray.h"
using namespace std;

int main()
{
    cout << "Best protocol analyser started..." << endl;
    cout << "Input file." << endl;

    string FileName;
    cin >> FileName;

    pcaparray s;
    s.ReadPcapFile(FileName);

    int k = 1;
    while(k)
    {
    cout << "1. Print Attribs" << endl;
    cout << "2. Print Current Paket data" << endl;
    cout << "3. Exit" << endl;

    cin >> k;
    system("cls");

    switch (k)
    {
        case 1:
            {
                s.PrintAttribs();
                break;
            }
        case 2:
            {
                cout << "Enter packet number to print" << endl;
                cin >> k;

                s.PrintPaketData(k);

                k=2;
                break;
            }
        case 3:
            {
                exit(1);
                break;
            }
    }
    system("pause");
    system("cls");
    }
    return 0;

}
