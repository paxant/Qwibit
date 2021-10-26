#ifndef THE_MAIN_WINDOW_H
#define THE_MAIN_WINDOW_H

#include <QDialog>

namespace Ui {
class The_main_window;
}

class The_main_window : public QDialog
{
    Q_OBJECT

public:
    explicit The_main_window(QWidget *parent = nullptr);
    ~The_main_window();

private slots:
    void on_pushButton_clicked();

    void on_pushButton_2_clicked();

private:
    Ui::The_main_window *ui;
    void Mane_Wind();
    void Clear_Inform();
    void Clear_Sett();
};

#endif // THE_MAIN_WINDOW_H
