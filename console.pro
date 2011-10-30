include(dissent.pro)
TEMPLATE = app
TARGET = console
INCLUDEPATH += src 
DEFINES += QT_NO_DEBUG_OUTPUT
DEFINES += QT_NO_WARNING_OUTPUT

# Input
SOURCES += src/Applications/ConsoleApp.cpp
