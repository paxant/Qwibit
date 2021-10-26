#include "comport.h"
#include <string>
HANDLE hSerial;
QTextStream out(stdout);
LPCTSTR sPortName = L"COM4";
void ComPort::Error_ST(char& error_St)
{
    hSerial = ::CreateFile(sPortName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (hSerial == INVALID_HANDLE_VALUE)
    {
        if (GetLastError() == ERROR_FILE_NOT_FOUND)
        {
            error_St = '2';
        }
        error_St = '1';
    }
    DCB dcbSerialParams = { 0 };
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    if (!GetCommState(hSerial, &dcbSerialParams))
    {
        error_St = '2';
    }
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    if (!SetCommState(hSerial, &dcbSerialParams))
    {
        error_St = '2';
    }
}
void ComPort::COMport_str(QString& COMP, char& error_St)
{
    hSerial = ::CreateFile(sPortName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    Error_ST(error_St);
    if(error_St == '0')
    {
    DWORD iSize;
    char sReceivedChar;
    int i =0;
    QString message;
    while (i < 255)
    {
        ReadFile(hSerial, &sReceivedChar, 1, &iSize, 0);  // получаем 1 байт
        if (iSize > 0)   // если что-то принято, выводим
            message += sReceivedChar;
        i++;
    }
    COMP.append(message);
    }
}
void ComPort::COMport_Int_Mass(int* Mass, char& error_St)
{
    hSerial = ::CreateFile(sPortName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    DCB dcbSerialParams = { 0 };
    dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
    dcbSerialParams.BaudRate = CBR_115200;
    dcbSerialParams.ByteSize = 8;
    dcbSerialParams.StopBits = ONESTOPBIT;
    dcbSerialParams.Parity = NOPARITY;
    Error_ST(error_St);
    if(error_St == '0')
    {
    DWORD iSize;
    char sReceivedChar;
    int i =0;
    QString message1, message2;
    while (i < 255)
    {
        ReadFile(hSerial, &sReceivedChar, 1, &iSize, 0);  // получаем 1 байт
        if (iSize > 0)   // если что-то принято, выводим
            message1 += sReceivedChar;
        i++;
    }
    Mass[0] = message1.toInt();
    while (i < 255)
    {
        ReadFile(hSerial, &sReceivedChar, 1, &iSize, 0);  // получаем 1 байт
        if (iSize > 0)   // если что-то принято, выводим
            message2 += sReceivedChar;
        i++;
    }
    Mass[1] = message2.toInt();
    }
}
void ComPort::COMport_giver(char * Message, char& error_St)
{
   hSerial = ::CreateFile(sPortName, GENERIC_READ | GENERIC_WRITE, 0, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
   Error_ST(error_St);
   DCB dcbSerialParams = { 0 };
   dcbSerialParams.DCBlength = sizeof(dcbSerialParams);
   dcbSerialParams.BaudRate = CBR_115200;
   dcbSerialParams.ByteSize = 8;
   dcbSerialParams.StopBits = ONESTOPBIT;
   dcbSerialParams.Parity = NOPARITY;
   DWORD dwSize = sizeof(Message);
   DWORD dwBytesWritten;
   if(error_St=='0')
   {
       BOOL iRet = WriteFile (hSerial,Message,dwSize,&dwBytesWritten,NULL);
   }
}
