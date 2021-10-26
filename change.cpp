#include "change.h"
#include "ui_change.h"
#include <QPixmap>
#include <QSound>
Change::Change(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Change)
{
    ui->setupUi(this);
    QSound::play(":/ressur/img/nah.wav");
    setWindowFlags(Qt::Dialog | Qt::MSWindowsFixedSizeDialogHint);
    int w = ui->back->width();
    int h = ui->back->height();
    QPixmap pix(":/ressur/img/back.jpg");
    ui->back->setPixmap(pix.scaled(w,h, Qt::KeepAspectRatio));
}

Change::~Change()
{
    delete ui;
}
