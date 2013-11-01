TEMPLATE = lib
TARGET = dissent
DEPENDPATH += 
CONFIG += qt debug
QT = core network concurrent

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
           src/Anonymity/BaseBulkRound.hpp \
           src/Anonymity/BlogDropRound.hpp \
           src/Anonymity/BulkRound.hpp \
           src/Anonymity/CSBulkRound.hpp \
           src/Anonymity/Log.hpp \
           src/Anonymity/NeffKeyShuffleRound.hpp \
           src/Anonymity/FastNeffKeyShuffleRound.hpp \
           src/Anonymity/NeffShuffleRound.hpp \
           src/Anonymity/NullRound.hpp \
           src/Anonymity/RepeatingBulkRound.hpp \
           src/Anonymity/Round.hpp \
           src/Anonymity/RoundStateMachine.hpp \
           src/Anonymity/ShuffleBlamer.hpp \
           src/Anonymity/ShuffleRound.hpp \
           src/Anonymity/ShuffleRoundBlame.hpp \
           src/Anonymity/Buddies/BuddyMonitor.hpp \
           src/Anonymity/Buddies/BuddyPolicy.hpp \
           src/Anonymity/Buddies/DynamicBuddyPolicy.hpp \
           src/Anonymity/Buddies/NullBuddyPolicy.hpp \
           src/Anonymity/Buddies/StaticBuddyPolicy.hpp \
           src/Anonymity/Sessions/Session.hpp \
           src/Anonymity/Sessions/SessionLeader.hpp \
           src/Anonymity/Sessions/SessionManager.hpp \
           src/Applications/AuthFactory.hpp \
           src/Applications/CommandLine.hpp \
           src/Applications/ConsoleSink.hpp \
           src/Applications/FileSink.hpp \
           src/Applications/Node.hpp \
           src/Applications/SessionFactory.hpp \
           src/Applications/Settings.hpp \
           src/ClientServer/CSBroadcast.hpp \
           src/ClientServer/CSConnectionAcquirer.hpp \
           src/ClientServer/CSForwarder.hpp \
           src/ClientServer/CSNetwork.hpp \
           src/ClientServer/CSOverlay.hpp \
           src/Connections/Bootstrapper.hpp \
           src/Connections/Connection.hpp \
           src/Connections/ConnectionAcquirer.hpp \
           src/Connections/ConnectionManager.hpp \
           src/Connections/ConnectionTable.hpp \
           src/Connections/DefaultNetwork.hpp \
           src/Connections/EmptyNetwork.hpp \
           src/Connections/ForwardingSender.hpp \
           src/Connections/FullyConnected.hpp \
           src/Connections/Id.hpp \
           src/Connections/IOverlaySender.hpp \
           src/Connections/Network.hpp \
           src/Connections/RelayAddress.hpp \
           src/Connections/RelayEdge.hpp \
           src/Connections/RelayEdgeListener.hpp \
           src/Connections/RelayForwarder.hpp \
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
           src/Identity/Authentication/IAuthenticate.hpp \
           src/Identity/Authentication/IAuthenticator.hpp \
           src/Identity/Authentication/LRSAuthenticate.hpp \
           src/Identity/Authentication/LRSAuthenticator.hpp \
           src/Identity/Authentication/NullAuthenticate.hpp \
           src/Identity/Authentication/NullAuthenticator.hpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticate.hpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticator.hpp \
           src/Identity/Group.hpp \
           src/Identity/GroupHolder.hpp \
           src/Identity/PrivateIdentity.hpp \
           src/Identity/PublicIdentity.hpp \
           src/Messaging/BufferSink.hpp \
           src/Messaging/DummySink.hpp \
           src/Messaging/Filter.hpp \
           src/Messaging/FilterObject.hpp \
           src/Messaging/GetDataCallback.hpp \
           src/Messaging/ISender.hpp \
           src/Messaging/ISink.hpp \
           src/Messaging/ISinkObject.hpp \
           src/Messaging/Request.hpp \
           src/Messaging/RequestResponder.hpp \
           src/Messaging/RequestHandler.hpp \
           src/Messaging/Response.hpp \
           src/Messaging/ResponseHandler.hpp \
           src/Messaging/RpcHandler.hpp \
           src/Messaging/SignalSink.hpp \
           src/Messaging/SinkMultiplexer.hpp \
           src/Messaging/Source.hpp \
           src/Messaging/SourceObject.hpp \
           src/Overlay/BaseOverlay.hpp \
           src/Overlay/BasicGossip.hpp \
           src/PeerReview/Acknowledgement.hpp \
           src/PeerReview/AcknowledgementLog.hpp \
           src/PeerReview/Entry.hpp \
           src/PeerReview/EntryParser.hpp \
           src/PeerReview/EntryLog.hpp \
           src/PeerReview/SendEntry.hpp \
           src/PeerReview/PRManager.hpp \
           src/PeerReview/ReceiveEntry.hpp \
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
           src/Tunnel/EntryTunnel.hpp \
           src/Tunnel/ExitTunnel.hpp \
           src/Tunnel/SessionEntryTunnel.hpp \
           src/Tunnel/SessionExitTunnel.hpp \
           src/Tunnel/SocksConnection.hpp \
           src/Tunnel/SocksTable.hpp \
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
           src/Web/BuddiesService.hpp \
           src/Web/EchoService.hpp \
           src/Web/GetDirectoryService.hpp \
           src/Web/GetFileService.hpp \
           src/Web/GetMessagesService.hpp \
           src/Web/MessageWebService.hpp \
           src/Web/SendMessageService.hpp \
           src/Web/SessionService.hpp \
           src/Web/WebServer.hpp \
           src/Web/WebService.hpp 

SOURCES += src/Anonymity/BaseBulkRound.cpp \
           src/Anonymity/BlogDropRound.cpp \
           src/Anonymity/BulkRound.cpp \
           src/Anonymity/CSBulkRound.cpp \
           src/Anonymity/Log.cpp \
           src/Anonymity/FastNeffKeyShuffleRound.cpp \
           src/Anonymity/NeffShuffleRound.cpp \
           src/Anonymity/NullRound.cpp \
           src/Anonymity/RepeatingBulkRound.cpp \
           src/Anonymity/Round.cpp \
           src/Anonymity/ShuffleBlamer.cpp \
           src/Anonymity/ShuffleRound.cpp \
           src/Anonymity/ShuffleRoundBlame.cpp \
           src/Anonymity/Buddies/BuddyMonitor.cpp \
           src/Anonymity/Buddies/BuddyPolicy.cpp \
           src/Anonymity/Buddies/DynamicBuddyPolicy.cpp \
           src/Anonymity/Buddies/NullBuddyPolicy.cpp \
           src/Anonymity/Buddies/StaticBuddyPolicy.cpp \
           src/Anonymity/Sessions/Session.cpp \
           src/Anonymity/Sessions/SessionLeader.cpp \
           src/Anonymity/Sessions/SessionManager.cpp \
           src/Applications/AuthFactory.cpp \
           src/Applications/CommandLine.cpp \
           src/Applications/ConsoleSink.cpp \
           src/Applications/FileSink.cpp \
           src/Applications/Node.cpp \
           src/Applications/SessionFactory.cpp \
           src/Applications/Settings.cpp \
           src/ClientServer/CSBroadcast.cpp \
           src/ClientServer/CSConnectionAcquirer.cpp \
           src/ClientServer/CSForwarder.cpp \
           src/ClientServer/CSNetwork.cpp \
           src/ClientServer/CSOverlay.cpp \
           src/Connections/Bootstrapper.cpp \
           src/Connections/Connection.cpp \
           src/Connections/ConnectionManager.cpp \
           src/Connections/ConnectionTable.cpp \
           src/Connections/FullyConnected.cpp \
           src/Connections/Id.cpp \
           src/Connections/RelayAddress.cpp \
           src/Connections/RelayEdge.cpp \
           src/Connections/RelayEdgeListener.cpp \
           src/Connections/RelayForwarder.cpp \
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
           src/Identity/Group.cpp \
           src/Identity/Authentication/LRSAuthenticate.cpp \
           src/Identity/Authentication/LRSAuthenticator.cpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticate.cpp \
           src/Identity/Authentication/PreExchangedKeyAuthenticator.cpp \
           src/Messaging/RpcHandler.cpp \
           src/Messaging/SignalSink.cpp \
           src/Overlay/BaseOverlay.cpp \
           src/Overlay/BasicGossip.cpp \
           src/PeerReview/AcknowledgementLog.cpp \
           src/PeerReview/Entry.cpp \
           src/PeerReview/EntryLog.cpp \
           src/PeerReview/EntryParser.cpp \
           src/PeerReview/PRManager.cpp \
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
           src/Tunnel/EntryTunnel.cpp \
           src/Tunnel/ExitTunnel.cpp \
           src/Tunnel/SessionEntryTunnel.cpp \
           src/Tunnel/SessionExitTunnel.cpp \
           src/Tunnel/SocksConnection.cpp \
           src/Tunnel/SocksTable.cpp \
           src/Utils/Logging.cpp \
           src/Utils/Random.cpp \
           src/Utils/Sleeper.cpp \
           src/Utils/StartStop.cpp \
           src/Utils/Time.cpp \
           src/Utils/Timer.cpp \
           src/Utils/TimerEvent.cpp \
           src/Utils/Utils.cpp \
           src/Web/WebServer.cpp \
           src/Web/BuddiesService.cpp \
           src/Web/GetDirectoryService.cpp \
           src/Web/GetFileService.cpp \
           src/Web/GetMessagesService.cpp \
           src/Web/SendMessageService.cpp \
           src/Web/SessionService.cpp \
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
