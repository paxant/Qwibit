#include "regist.h"
#include <QWidget>

    regist::regist(QWidget *parent) :
        QDialog(parent),
        ui(new Ui::regist)
    {
        ui->setupUi(this);
    }

    Log::~Log()
    {
        delete ui;
    }

