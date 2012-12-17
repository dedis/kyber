TARGET=helloworld
QT += network
QT -= gui

INCLUDEPATH += ../../src
LIBS += -L../../lib -lqhttpserver

SOURCES=helloworld.cpp
HEADERS=helloworld.h
