#include "the_main_window.h"
#include "ui_the_main_window.h"
static bool Settings(false);
static bool Information(false);
The_main_window::The_main_window(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::The_main_window)
{
    ui->setupUi(this);
    ui->pushButton->setStyleSheet("QPushButton{background: transparent;}");
    ui->pushButton_2->setStyleSheet("QPushButton{background: transparent;}");
    QPixmap pix(":/ressur/img/pref.png");
    int w = ui->Zn_Pr->width();
    int h = ui->Zn_Pr->height();
    ui->Zn_Pr->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
    QPixmap hix(":/ressur/img/inf.png");
    ui->Zn_Pr_2->setPixmap(hix.scaled(w,h, Qt::KeepAspectRatio));
    int go = ui->label_5->width();
    int ho = ui->label_5->height();
    QPixmap image(":/ressur/img/backg.png");
    ui->label_5->setPixmap(image.scaled(go, ho));
    Mane_Wind();
    ui->label_6->setStyleSheet("background-color: rgba(255, 255, 255, 90);");
}

The_main_window::~The_main_window()
{
    delete ui;
}
void The_main_window::Clear_Inform()
{
    ui->Infor_txt->clear();
}
void The_main_window::Clear_Sett()
{

}
void The_main_window::Mane_Wind()
{
    QPixmap mage(":/ressur/img/Tp.png");
    QPixmap mage_2(":/ressur/img/Vl.png");
    int gi = ui->mage->width();
    int hi = ui->mage->height();
    ui->mage->setPixmap(mage.scaled(gi, hi, Qt::KeepAspectRatio));
    ui->mage_2->setPixmap(mage_2.scaled(gi,hi, Qt::KeepAspectRatio));
    ui->label_7->setText("Температура");
    ui->label_8->setText("  Влажность");
}
static void setting()
{
    if (Settings == false)
           Settings = true;
       else
           Settings = false;
}
void The_main_window::on_pushButton_clicked()
{
    Information = false;
    setting();
    if(Settings == true)
    {
        ui->mage->clear();
        ui->mage_2->clear();
        ui->label_7->clear();
        ui->label_8->clear();
        Clear_Inform();
    }
    if(Settings == false)
    {
        Mane_Wind();
        Clear_Sett();
    }
}
static void Inf()
{
    if (Information  == false)
           Information = true;
       else
           Information = false;
}

void The_main_window::on_pushButton_2_clicked()
{
    Settings = false;
    Inf();
    if(Information == true)
    {
        ui->mage->clear();
        ui->mage_2->clear();
        ui->label_7->clear();
        ui->label_8->clear();
        Clear_Sett();
        ui->Infor_txt->setText("ЗДЕСЬ ДОЛЖНА БЫТЬ ВАЖНАЯ ИНФОРМАЦИЯ, НЕ ЗНАЮ КАКАЯ \n Погрешность измерения влажности 5% \n Погрешность измерения температуры 2%");
    }
    if(Information == false)
    {
        Clear_Inform();
        Mane_Wind();
    }
}

