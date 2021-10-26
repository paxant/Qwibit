#include "log.h"
#include "ui_log.h"
#include "qwibit.h"
#include "the_main_window.h"
Log::Log(QWidget *parent) :
    QDialog(parent),
    ui(new Ui::Log)
{
    ui->setupUi(this);
    setWindowFlags(Qt::Dialog | Qt::MSWindowsFixedSizeDialogHint);
}

Log::~Log()
{
    delete ui;
}

bool Log::Pass_prov(QString log, QString pa)
{
    return true;
}

void Log::on_pushButton_clicked()
{
    The_main_window window;
    QString login = ui -> login -> text();
    QString pass = ui ->pass -> text();
    if(Pass_prov(login, pass))
    {
        QWidget::close();
        setWindowTitle("Qwibit");
        window.exec();
    }
}

