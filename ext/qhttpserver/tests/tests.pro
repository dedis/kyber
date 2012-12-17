TEMPLATE = app
QT += network

SOURCES = test.cpp

LIBS += -L../lib/ -lqhttpserver
INCLUDEPATH += .\
 ../src
