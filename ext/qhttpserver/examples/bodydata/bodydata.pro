QT += network
QT -= gui
CONFIG += debug

INCLUDEPATH += ../../src
LIBS += -L../../lib -lqhttpserver

SOURCES=bodydata.cpp
HEADERS=bodydata.h
