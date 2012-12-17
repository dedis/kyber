QT += network
QT -= gui
CONFIG += debug

INCLUDEPATH += ../../src
LIBS += -L../../lib -lqhttpserver

SOURCES=greeting.cpp
HEADERS=greeting.h
