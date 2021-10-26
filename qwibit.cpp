#include "qwibit.h"
#include "ui_qwibit.h"
#include "log.h"
#include "registr.h"
#include <QMessageBox>
#include <QPixmap>
#include <QThread>
#include <change.h>
#include <QSound>
#include <comport.h>
Qwibit::Qwibit(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::Qwibit)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::MSWindowsFixedSizeDialogHint);
    ComPort COMPT;
    QString COMP;
    char error_St = '0';
    COMPT.COMport_str(COMP, error_St);
    COMPT.~ComPort();
    int w = ui->image->width();
    int h = ui->image->height();
    switch('0')
    {
        case '0':
          {
             //QSound::play(":/ressur/img/MINI.wav");
             /*if(COMP == "4e6f2064617461FF")
             {
                 ui->pushButton->setEnabled(false);
             }
             else
             {
                 ui->Proff->setEnabled(false);
             }*/
             QPixmap pix(":/ressur/img/connect.png");
             ui->image->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
             ui->textVV->setAlignment(Qt::AlignCenter);
             ui->textVV->setText("<font size =24><b>Устройство <br> подключено</b></font>");
        break;
          }
        case '1':
    {
                 QPixmap pix(":/ressur/img/disconnect.png");
                 ui->image->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
                 ui->pushButton->setEnabled(false);
                 ui->Proff->setEnabled(false);
                 ui->textVV->setAlignment(Qt::AlignCenter);
                 ui->textVV->setText("<font size =24><b>Устройство не <br> подключено</b></font>");
                 QMessageBox::information(this, "Ошибка", "Произошла неизвестная ошибка");
                 break;
    }
        case '2':
              {
                 QPixmap pix(":/ressur/img/disconnect.png");
                 ui->image->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
                 ui->pushButton->setEnabled(false);
                 ui->Proff->setEnabled(false);
                 ui->textVV->setAlignment(Qt::AlignCenter);
                 ui->textVV->setText("<font size =24><b>Устройство не <br> подключено</b></font>");
                 QMessageBox::information(this, "Ошибка", "Порт не найден");
                 break;
              }
    }
}

Qwibit::~Qwibit()
{
    delete ui;
}

void Qwibit::on_pushButton_clicked()
{
    Qwibit::close();
    Log window_log;
    window_log.setWindowTitle("Qwibit");
    window_log.exec();
}


void Qwibit::on_Quitt_triggered()
{
    QApplication::quit();
}


void Qwibit::on_Proff_clicked()
{
    registr window_reg;
    window_reg.setWindowTitle("Qwibit");
    window_reg.exec();
}


void Qwibit::on_pushButton_2_clicked()
{
    Change window_ch;
    window_ch.setWindowTitle("Пошел нахуй");
    window_ch.setStyleSheet("background-color:black;");
    window_ch.exec();
}
