#ifndef QWIBIT_H
#define QWIBIT_H

#include <QMainWindow>

QT_BEGIN_NAMESPACE
namespace Ui { class Qwibit; }
QT_END_NAMESPACE

class Qwibit : public QMainWindow
{
    Q_OBJECT

public:
    Qwibit(QWidget *parent = nullptr);
    ~Qwibit();

private slots:
    void on_pushButton_clicked();

    void on_label_linkActivated(const QString &link);

    void on_Quitt_triggered();

    void on_Proff_clicked();

    void on_Zash_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::Qwibit *ui;
    Ui::Qwibit *main_window;
};
#endif // QWIBIT_H
