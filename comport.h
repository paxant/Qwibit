#ifndef COMPORT_H
#define COMPORT_H
#include <QString>
#include<windows.h>
#include<QTextStream>
class ComPort
{
private:
    void Error_ST(char& error_St);
public:
    void COMport_str(QString& COMP, char& error_St);
    void COMport_Int_Mass(int* Mass, char& error_St);
    void COMport_giver(char * Message, char& error_St);
};

#endif // COMPORT_H
