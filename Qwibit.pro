QT       += core gui
QT += serialport
QT += multimedia multimediawidgets
greaterThan(QT_MAJOR_VERSION, 4): QT += widgets
CONFIG += c++11
# You can make your code fail to compile if it uses deprecated APIs.
# In order to do so, uncomment the following line.
#DEFINES += QT_DISABLE_DEPRECATED_BEFORE=0x060000    # disables all the APIs deprecated before Qt 6.0.0
win32:RC_FILE = icon.rc
SOURCES += \
    change.cpp \
    comport.cpp \
    log.cpp \
    main.cpp \
    myrsa.cpp \
    qwibit.cpp \
    registr.cpp \
    the_main_window.cpp

HEADERS += \
    change.h \
    comport.h \
    log.h \
    myrsa.h \
    qwibit.h \
    registr.h \
    the_main_window.h

FORMS += \
    change.ui \
    log.ui \
    qwibit.ui \
    registr.ui \
    the_main_window.ui

TRANSLATIONS += \
    Qwibit_myv_RU.ts
CONFIG += lrelease
CONFIG += embed_translations

# Default rules for deployment.
qnx: target.path = /tmp/$${TARGET}/bin
else: unix:!android: target.path = /opt/$${TARGET}/bin
!isEmpty(target.path): INSTALLS += target

RESOURCES += \
    resourse.qrc

DISTFILES += \
    icon.rc
