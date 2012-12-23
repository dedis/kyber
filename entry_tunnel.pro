include(dissent.pro)
TEMPLATE = app
TARGET = entry_tunnel
INCLUDEPATH += src 
#DEFINES += QT_NO_DEBUG_OUTPUT
#DEFINES += QT_NO_WARNING_OUTPUT

# Input
SOURCES += src/Tunnel/SoloEntryTunnel.cpp
