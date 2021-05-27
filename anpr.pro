TEMPLATE = app
CONFIG += console c++11
CONFIG -= app_bundle
CONFIG -= qt

SOURCES += main.cpp \
    pcappacket.cpp \
    pcaparray.cpp

HEADERS += \
    pcappacket.h \
    pcaparray.h

