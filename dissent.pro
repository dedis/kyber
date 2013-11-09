TEMPLATE = lib
TARGET = dissent
DEPENDPATH += 
CONFIG += qt debug
QT = core network
greaterThan(QT_MAJOR_VERSION, 4):QT += concurrent

# Dissent Wire protocol version
DEFINES += "VERSION=3"

# COMMENT THE BELOW TO MAKE DISSENT RUN WITH A SECURE SHUFFLE, THEN
# qmake *.pro, make clean, make...
DEFINES += FAST_NEFF_SHUFFLE

# UNCOMMENT THE FOLLOWING TO MAKE DISSENT NICE FOR DEMOS
# DEFINES += DEMO_SESSION

# UNCOMMENT THE FOLLOWING TO ENABLE BLOG DROP BLAME FOR CSBULK
# DEFINES += CS_BLOG_DROP

QMAKE_CXXFLAGS += -Werror -std=c++11
QMAKE_CFLAGS += -Werror

# External Libraries

# CryptoPP
DEFINES += CRYPTOPP
LIBS += -lcryptopp

# QHttpServer
INCLUDEPATH += ext/qhttpserver/src
HEADERS += ext/qhttpserver/src/qhttpconnection.h \
           ext/qhttpserver/src/qhttprequest.h \
           ext/qhttpserver/src/qhttpresponse.h \
           ext/qhttpserver/src/qhttpserver.h
SOURCES += ext/qhttpserver/src/qhttpconnection.cpp \
           ext/qhttpserver/src/qhttprequest.cpp \
           ext/qhttpserver/src/qhttpresponse.cpp \
           ext/qhttpserver/src/qhttpserver.cpp

# Joyent HTTP Parser in QHttpServer
INCLUDEPATH += ext/qhttpserver/http-parser
HEADERS += ext/qhttpserver/http-parser/http_parser.h
SOURCES += ext/qhttpserver/http-parser/http_parser.c

# Qt-JSON
INCLUDEPATH += ext/qt-json
HEADERS += ext/qt-json/json.h
SOURCES += ext/qt-json/json.cpp

# Qxt Command-line parsing
INCLUDEPATH += ext/qxt
HEADERS += ext/qxt/qxtcommandoptions.h \
           ext/qxt/qxtglobal.h
SOURCES += ext/qxt/qxtcommandoptions.cpp

# Dissent
INCLUDEPATH += src

HEADERS += src/Dissent.hpp \
           src/Anonymity/BaseDCNetRound.hpp \
           src/Anonymity/CSDCNetRound.hpp \
           src/Anonymity/Log.hpp \
           src/Anonymity/NeffShuffleRound.hpp \
           src/Anonymity/NullRound.hpp \
           src/Anonymity/Round.hpp \
           src/Anonymity/RoundFactory.hpp \
           src/Anonymity/RoundStateMachine.hpp \
           src/Applications/CommandLine.hpp \
           src/Applications/ConsoleSink.hpp \
           src/Applications/FileSink.hpp \
           src/Applications/Node.hpp \
           src/Applications/Settings.hpp \
           src/ClientServer/Broadcaster.hpp \
           src/ClientServer/ClientConnectionAcquirer.hpp \
           src/ClientServer/Forwarder.hpp \
           src/ClientServer/Overlay.hpp \
           src/ClientServer/ServerConnectionAcquirer.hpp \
           src/Connections/Connection.hpp \
           src/Connections/ConnectionAcquirer.hpp \
           src/Connections/ConnectionManager.hpp \
           src/Connections/ConnectionTable.hpp \
           src/Connections/ForwardingSender.hpp \
           src/Connections/Id.hpp \
           src/Connections/IForwarder.hpp \
           src/Connections/IOverlaySender.hpp \
           src/Crypto/AsymmetricKey.hpp \
           src/Crypto/DsaPrivateKey.hpp \
           src/Crypto/DsaPublicKey.hpp \
           src/Crypto/NeffShuffle.hpp \
           src/Crypto/RsaPrivateKey.hpp \
           src/Crypto/RsaPublicKey.hpp \
           src/Crypto/CryptoRandom.hpp \
           src/Crypto/DiffieHellman.hpp \
           src/Crypto/Hash.hpp \
           src/Crypto/Integer.hpp \
           src/Crypto/KeyShare.hpp \
           src/Crypto/LRSPrivateKey.hpp \
           src/Crypto/LRSPublicKey.hpp \
           src/Crypto/LRSSignature.hpp \
           src/Crypto/OnionEncryptor.hpp \
           src/Crypto/ThreadedOnionEncryptor.hpp \
           src/Crypto/Serialization.hpp \
           src/Crypto/Utils.hpp \
           src/Crypto/AbstractGroup/CppECGroup.hpp \
           src/Crypto/AbstractGroup/CppECElementData.hpp \
           src/Crypto/AbstractGroup/ElementData.hpp \
           src/Crypto/AbstractGroup/IntegerGroup.hpp \
           src/Crypto/AbstractGroup/Element.hpp \
           src/Crypto/AbstractGroup/AbstractGroup.hpp \
           src/Crypto/AbstractGroup/ECParams.hpp \
           src/Crypto/AbstractGroup/IntegerElementData.hpp \
           src/Crypto/BlogDrop/PublicKey.hpp \
           src/Crypto/BlogDrop/Parameters.hpp \
           src/Crypto/BlogDrop/BlogDropUtils.hpp \
           src/Crypto/BlogDrop/BlogDropServer.hpp \
           src/Crypto/BlogDrop/HashingGenServerCiphertext.hpp \
           src/Crypto/BlogDrop/BlogDropClient.hpp \
           src/Crypto/BlogDrop/HashingGenClientCiphertext.hpp \
           src/Crypto/BlogDrop/PublicKeySet.hpp \
           src/Crypto/BlogDrop/ChangingGenServerCiphertext.hpp \
           src/Crypto/BlogDrop/ElGamalServerCiphertext.hpp \
           src/Crypto/BlogDrop/ServerCiphertext.hpp \
           src/Crypto/BlogDrop/BlogDropAuthor.hpp \
           src/Crypto/BlogDrop/ClientCiphertext.hpp \
           src/Crypto/BlogDrop/Plaintext.hpp \
           src/Crypto/BlogDrop/CiphertextFactory.hpp \
           src/Crypto/BlogDrop/PrivateKey.hpp \
           src/Crypto/BlogDrop/ElGamalClientCiphertext.hpp \
           src/Crypto/BlogDrop/ChangingGenClientCiphertext.hpp \
           src/Identity/PublicIdentity.hpp \
           src/Identity/PrivateIdentity.hpp \
           src/Identity/Roster.hpp \
           src/Messaging/BufferSink.hpp \
           src/Messaging/DummySink.hpp \
           src/Messaging/Filter.hpp \
           src/Messaging/FilterObject.hpp \
           src/Messaging/GetDataCallback.hpp \
           src/Messaging/ISender.hpp \
           src/Messaging/ISink.hpp \
           src/Messaging/ISinkObject.hpp \
           src/Messaging/Message.hpp \
           src/Messaging/Request.hpp \
           src/Messaging/RequestResponder.hpp \
           src/Messaging/RequestHandler.hpp \
           src/Messaging/Response.hpp \
           src/Messaging/ResponseHandler.hpp \
           src/Messaging/RpcHandler.hpp \
           src/Messaging/SignalSink.hpp \
           src/Messaging/SinkMultiplexer.hpp \
           src/Messaging/State.hpp \
           src/Messaging/StateData.hpp \
           src/Messaging/StateMachine.hpp \
           src/Messaging/Source.hpp \
           src/Messaging/SourceObject.hpp \
           src/Session/ClientRegister.hpp \
           src/Session/ClientSession.hpp \
           src/Session/ClientStates.hpp \
           src/Session/SerializeList.hpp \
           src/Session/ServerAgree.hpp \
           src/Session/ServerEnlist.hpp \
           src/Session/ServerEnlisted.hpp \
           src/Session/ServerInit.hpp \
           src/Session/ServerList.hpp \
           src/Session/ServerQueued.hpp \
           src/Session/ServerSession.hpp \
           src/Session/ServerStart.hpp \
           src/Session/ServerStates.hpp \
           src/Session/ServerStop.hpp \
           src/Session/ServerVerifyList.hpp \
           src/Session/Session.hpp \
           src/Session/SessionData.hpp \
           src/Session/SessionMessage.hpp \
           src/Session/SessionSharedState.hpp \
           src/Session/SessionState.hpp \
           src/Transports/Address.hpp \
           src/Transports/AddressFactory.hpp \
           src/Transports/BufferAddress.hpp \
           src/Transports/BufferEdge.hpp \
           src/Transports/BufferEdgeListener.hpp \
           src/Transports/Edge.hpp \
           src/Transports/EdgeFactory.hpp \
           src/Transports/EdgeListener.hpp \
           src/Transports/EdgeListenerFactory.hpp \
           src/Transports/TcpAddress.hpp \
           src/Transports/TcpEdge.hpp \
           src/Transports/TcpEdgeListener.hpp \
           src/Utils/Logging.hpp \
           src/Utils/Random.hpp \
           src/Utils/QRunTimeError.hpp \
           src/Utils/Serialization.hpp \
           src/Utils/SignalCounter.hpp \
           src/Utils/Sleeper.hpp \
           src/Utils/StartStop.hpp \
           src/Utils/StartStopSlots.hpp \
           src/Utils/Time.hpp \
           src/Utils/Timer.hpp \
           src/Utils/TimerCallback.hpp \
           src/Utils/TimerEvent.hpp \
           src/Utils/Triggerable.hpp \
           src/Utils/Triple.hpp \
           src/Utils/Utils.hpp \
           src/Web/EchoService.hpp \
           src/Web/GetDirectoryService.hpp \
           src/Web/GetFileService.hpp \
           src/Web/GetMessagesService.hpp \
           src/Web/SendMessageService.hpp \
           src/Web/SessionService.hpp \
           src/Web/MessageWebService.hpp \
           src/Web/WebServer.hpp \
           src/Web/WebService.hpp 

SOURCES += src/Anonymity/BaseDCNetRound.cpp \
           src/Anonymity/CSDCNetRound.cpp \
           src/Anonymity/Log.cpp \
           src/Anonymity/NullRound.cpp \
           src/Anonymity/NeffShuffleRound.cpp \
           src/Anonymity/Round.cpp \
           src/Anonymity/RoundFactory.cpp \
           src/Applications/CommandLine.cpp \
           src/Applications/ConsoleSink.cpp \
           src/Applications/FileSink.cpp \
           src/Applications/Settings.cpp \
           src/ClientServer/Broadcaster.cpp \
           src/ClientServer/ClientConnectionAcquirer.cpp \
           src/ClientServer/Forwarder.cpp \
           src/ClientServer/Overlay.cpp \
           src/ClientServer/ServerConnectionAcquirer.cpp \
           src/Connections/Connection.cpp \
           src/Connections/ConnectionManager.cpp \
           src/Connections/ConnectionTable.cpp \
           src/Connections/Id.cpp \
           src/Crypto/AsymmetricKey.cpp \
           src/Crypto/DsaPrivateKey.cpp \
           src/Crypto/DsaPublicKey.cpp \
           src/Crypto/NeffShuffle.cpp \
           src/Crypto/DiffieHellman.cpp \
           src/Crypto/KeyShare.cpp \
           src/Crypto/LRSPrivateKey.cpp \
           src/Crypto/LRSPublicKey.cpp \
           src/Crypto/OnionEncryptor.cpp \
           src/Crypto/RsaPrivateKey.cpp \
           src/Crypto/ThreadedOnionEncryptor.cpp \
           src/Crypto/AbstractGroup/IntegerGroup.cpp \
           src/Crypto/AbstractGroup/AbstractGroup.cpp \
           src/Crypto/AbstractGroup/CppECGroup.cpp \
           src/Crypto/AbstractGroup/ECParams.cpp \
           src/Crypto/BlogDrop/CiphertextFactory.cpp \
           src/Crypto/BlogDrop/BlogDropServer.cpp \
           src/Crypto/BlogDrop/PublicKeySet.cpp \
           src/Crypto/BlogDrop/ChangingGenServerCiphertext.cpp \
           src/Crypto/BlogDrop/HashingGenClientCiphertext.cpp \
           src/Crypto/BlogDrop/ChangingGenClientCiphertext.cpp \
           src/Crypto/BlogDrop/ElGamalServerCiphertext.cpp \
           src/Crypto/BlogDrop/Parameters.cpp \
           src/Crypto/BlogDrop/ClientCiphertext.cpp \
           src/Crypto/BlogDrop/BlogDropUtils.cpp \
           src/Crypto/BlogDrop/ServerCiphertext.cpp \
           src/Crypto/BlogDrop/BlogDropClient.cpp \
           src/Crypto/BlogDrop/Plaintext.cpp \
           src/Crypto/BlogDrop/ElGamalClientCiphertext.cpp \
           src/Crypto/BlogDrop/HashingGenServerCiphertext.cpp \
           src/Crypto/BlogDrop/PublicKey.cpp \
           src/Crypto/BlogDrop/BlogDropAuthor.cpp \
           src/Crypto/BlogDrop/PrivateKey.cpp \
           src/Identity/Roster.cpp \
           src/Messaging/RpcHandler.cpp \
           src/Messaging/SignalSink.cpp \
           src/Session/ClientSession.cpp \
           src/Session/ServerSession.cpp \
           src/Session/Session.cpp \
           src/Session/SessionSharedState.cpp \
           src/Transports/Address.cpp \
           src/Transports/AddressFactory.cpp \
           src/Transports/BufferAddress.cpp \
           src/Transports/BufferEdge.cpp \
           src/Transports/BufferEdgeListener.cpp \
           src/Transports/Edge.cpp \
           src/Transports/EdgeFactory.cpp \
           src/Transports/EdgeListener.cpp \
           src/Transports/EdgeListenerFactory.cpp \
           src/Transports/TcpAddress.cpp \
           src/Transports/TcpEdge.cpp \
           src/Transports/TcpEdgeListener.cpp \
           src/Utils/Logging.cpp \
           src/Utils/Random.cpp \
           src/Utils/Sleeper.cpp \
           src/Utils/StartStop.cpp \
           src/Utils/Time.cpp \
           src/Utils/Timer.cpp \
           src/Utils/TimerEvent.cpp \
           src/Utils/Utils.cpp \
           src/Web/GetDirectoryService.cpp \
           src/Web/GetFileService.cpp \
           src/Web/GetMessagesService.cpp \
           src/Web/SendMessageService.cpp \
           src/Web/SessionService.cpp \
           src/Web/WebServer.cpp \
           src/Web/WebService.cpp

HEADERS += src/Crypto/CryptoPP/DsaPublicKeyImpl.hpp \
           src/Crypto/CryptoPP/Helper.hpp \
           src/Crypto/CryptoPP/RsaPublicKeyImpl.hpp \

SOURCES += src/Crypto/CryptoPP/CryptoRandomImpl.cpp \
           src/Crypto/CryptoPP/DiffieHellmanImpl.cpp \
           src/Crypto/CryptoPP/DsaPrivateKeyImpl.cpp \
           src/Crypto/CryptoPP/DsaPublicKeyImpl.cpp \
           src/Crypto/CryptoPP/HashImpl.cpp \
           src/Crypto/CryptoPP/IntegerImpl.cpp \
           src/Crypto/CryptoPP/RsaPrivateKeyImpl.cpp \
           src/Crypto/CryptoPP/RsaPublicKeyImpl.cpp
