#include "registr.h"
#include "ui_registr.h"
#include "myrsa.h"
#include "comport.h"
#include <iostream>
registr::registr(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::registr)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::MSWindowsFixedSizeDialogHint);
}

registr::~registr()
{
    delete ui;
}

void registr::on_pushButton_clicked()
{
    QString login = ui->lineEdit-> text();
    QString pass = ui ->lineEdit_2-> text();
    QString pass_pov = ui->lineEdit_3->text();
    ui->label_4->clear();
    ui->label_5->clear();
    ui->label_6->clear();
    ui->label_2->setText("Пароль");
    if(login.length() < 1)
    {
        int w = ui->label_6->width();
        int h = ui->label_6->height();
        QPixmap pix(":/ressur/img/err.png");
        ui->label_6->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
    }
    if(pass.length() > 8 )
    {
        int w = ui->label_5->width();
        int h = ui->label_5->height();
        QPixmap pix(":/ressur/img/err.png");
        ui->label_5->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
        ui->label_2->setText("<font color = red><\\font>Пароль больше 8");
    }
    else if(pass.length()< 1)
    {
        int w = ui->label_5->width();
        int h = ui->label_5->height();
        QPixmap pix(":/ressur/img/err.png");
        ui->label_5->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
        ui->label_2->setText("<font color = red><\\font>Вы не ввели пароль");
    }
    else if(pass !=pass_pov)
    {
        int w = ui->label_4->width();
        int h = ui->label_4->height();
        QPixmap pix(":/ressur/img/err.png");
        ui->label_4->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
    }
    else
    {
        MyRSA rsa;   
        ComPort port;
        int Pub_key[2];
        char error_St = '0';
        port.COMport_Int_Mass(Pub_key, error_St);
        rsa.pub_key(Pub_key[0], Pub_key[1]);
        char ch_login[PLAINTEXT_SIZE], ch_pass[PLAINTEXT_SIZE];
        strncpy(ch_login, qPrintable(login), PLAINTEXT_SIZE-1);
        strncpy(ch_pass, qPrintable(pass), PLAINTEXT_SIZE-1);
        char en_login[CIPHERTEXT_SIZE], en_pass[CIPHERTEXT_SIZE];
        rsa.rsa_e_d(ch_login, en_login);
        rsa.rsa_e_d(ch_pass, en_pass);
        rsa.~MyRSA();
        port.COMport_giver(en_login, error_St);
        port.COMport_giver(en_pass, error_St);
    }
}

