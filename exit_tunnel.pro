include(dissent.pro)
TEMPLATE = app
TARGET = exit_tunnel
INCLUDEPATH += src 
#DEFINES += QT_NO_DEBUG_OUTPUT
#DEFINES += QT_NO_WARNING_OUTPUT

# Input
SOURCES += src/Tunnel/SoloExitTunnel.cpp
