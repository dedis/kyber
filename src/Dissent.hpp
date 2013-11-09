#ifndef DISSENT_DISSENT_H_GUARD
#define DISSENT_DISSENT_H_GUARD

#include "Anonymity/BaseDCNetRound.hpp"
#include "Anonymity/CSDCNetRound.hpp"
#include "Anonymity/Log.hpp"
#include "Anonymity/NeffShuffleRound.hpp"
#include "Anonymity/NullRound.hpp"
#include "Anonymity/Round.hpp"
#include "Anonymity/RoundFactory.hpp"

#include "Applications/CommandLine.hpp"
#include "Applications/ConsoleSink.hpp"
#include "Applications/FileSink.hpp"
#include "Applications/Node.hpp"
#include "Applications/Settings.hpp"

#include "ClientServer/Broadcaster.hpp"
#include "ClientServer/ClientConnectionAcquirer.hpp"
#include "ClientServer/Forwarder.hpp"
#include "ClientServer/Overlay.hpp"
#include "ClientServer/ServerConnectionAcquirer.hpp"

#include "Connections/Connection.hpp"
#include "Connections/ConnectionAcquirer.hpp"
#include "Connections/ConnectionManager.hpp"
#include "Connections/ConnectionTable.hpp"
#include "Connections/Id.hpp"
#include "Connections/IOverlaySender.hpp"

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/DsaPrivateKey.hpp"
#include "Crypto/DsaPublicKey.hpp"
#include "Crypto/NeffShuffle.hpp"
#include "Crypto/RsaPrivateKey.hpp"
#include "Crypto/RsaPublicKey.hpp"
#include "Crypto/CryptoRandom.hpp"
#include "Crypto/DiffieHellman.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Integer.hpp"
#include "Crypto/KeyShare.hpp"
#include "Crypto/LRSPrivateKey.hpp"
#include "Crypto/LRSPublicKey.hpp"
#include "Crypto/LRSSignature.hpp"
#include "Crypto/OnionEncryptor.hpp"
#include "Crypto/Serialization.hpp"
#include "Crypto/ThreadedOnionEncryptor.hpp"
#include "Crypto/Utils.hpp"

#include "Crypto/AbstractGroup/CppECGroup.hpp"
#include "Crypto/AbstractGroup/CppECElementData.hpp"
#include "Crypto/AbstractGroup/ElementData.hpp"
#include "Crypto/AbstractGroup/IntegerGroup.hpp"
#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/AbstractGroup/AbstractGroup.hpp"
#include "Crypto/AbstractGroup/ECParams.hpp"
#include "Crypto/AbstractGroup/IntegerElementData.hpp"

#include "Crypto/BlogDrop/PublicKey.hpp"
#include "Crypto/BlogDrop/Parameters.hpp"
#include "Crypto/BlogDrop/BlogDropUtils.hpp"
#include "Crypto/BlogDrop/BlogDropServer.hpp"
#include "Crypto/BlogDrop/HashingGenServerCiphertext.hpp"
#include "Crypto/BlogDrop/BlogDropClient.hpp"
#include "Crypto/BlogDrop/HashingGenClientCiphertext.hpp"
#include "Crypto/BlogDrop/PublicKeySet.hpp"
#include "Crypto/BlogDrop/ChangingGenServerCiphertext.hpp"
#include "Crypto/BlogDrop/ElGamalServerCiphertext.hpp"
#include "Crypto/BlogDrop/ServerCiphertext.hpp"
#include "Crypto/BlogDrop/BlogDropAuthor.hpp"
#include "Crypto/BlogDrop/ClientCiphertext.hpp"
#include "Crypto/BlogDrop/Plaintext.hpp"
#include "Crypto/BlogDrop/CiphertextFactory.hpp"
#include "Crypto/BlogDrop/PrivateKey.hpp"
#include "Crypto/BlogDrop/ElGamalClientCiphertext.hpp"
#include "Crypto/BlogDrop/ChangingGenClientCiphertext.hpp"

#include "Identity/PublicIdentity.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/Roster.hpp"

#include "Messaging/BufferSink.hpp"
#include "Messaging/DummySink.hpp"
#include "Messaging/Filter.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/GetDataCallback.hpp" 
#include "Messaging/ISender.hpp"
#include "Messaging/ISink.hpp"
#include "Messaging/ISinkObject.hpp"
#include "Messaging/Message.hpp"
#include "Messaging/Request.hpp"
#include "Messaging/RequestHandler.hpp"
#include "Messaging/Response.hpp"
#include "Messaging/ResponseHandler.hpp"
#include "Messaging/RpcHandler.hpp"
#include "Messaging/SignalSink.hpp"
#include "Messaging/SinkMultiplexer.hpp"
#include "Messaging/State.hpp"
#include "Messaging/StateData.hpp"
#include "Messaging/StateMachine.hpp"
#include "Messaging/Source.hpp"
#include "Messaging/SourceObject.hpp"

#include "Session/ClientRegister.hpp"
#include "Session/ClientSession.hpp"
#include "Session/ClientStates.hpp"
#include "Session/SerializeList.hpp"
#include "Session/ServerAgree.hpp"
#include "Session/ServerEnlist.hpp"
#include "Session/ServerEnlisted.hpp"
#include "Session/ServerInit.hpp"
#include "Session/ServerList.hpp"
#include "Session/ServerQueued.hpp"
#include "Session/ServerSession.hpp"
#include "Session/ServerStart.hpp"
#include "Session/ServerStates.hpp"
#include "Session/ServerStop.hpp"
#include "Session/ServerVerifyList.hpp"
#include "Session/Session.hpp"
#include "Session/SessionData.hpp"
#include "Session/SessionMessage.hpp"
#include "Session/SessionSharedState.hpp"
#include "Session/SessionState.hpp"

#include "Transports/Address.hpp"
#include "Transports/AddressFactory.hpp"
#include "Transports/BufferAddress.hpp"
#include "Transports/BufferEdge.hpp"
#include "Transports/BufferEdgeListener.hpp"
#include "Transports/Edge.hpp"
#include "Transports/EdgeFactory.hpp"
#include "Transports/EdgeListener.hpp"
#include "Transports/EdgeListenerFactory.hpp"
#include "Transports/TcpAddress.hpp"
#include "Transports/TcpEdge.hpp"
#include "Transports/TcpEdgeListener.hpp"

#include "Utils/Logging.hpp"
#include "Utils/QRunTimeError.hpp"
#include "Utils/Random.hpp"
#include "Utils/Serialization.hpp"
#include "Utils/SignalCounter.hpp"
#include "Utils/Sleeper.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/StartStopSlots.hpp"
#include "Utils/Time.hpp"
#include "Utils/Timer.hpp"
#include "Utils/TimerCallback.hpp"
#include "Utils/TimerEvent.hpp"
#include "Utils/Triggerable.hpp"
#include "Utils/Triple.hpp"
#include "Utils/Utils.hpp"

#include "Web/EchoService.hpp"
#include "Web/GetDirectoryService.hpp"
#include "Web/GetFileService.hpp"
#include "Web/GetMessagesService.hpp"
#include "Web/SendMessageService.hpp"
#include "Web/MessageWebService.hpp"
#include "Web/WebServer.hpp"
#include "Web/WebService.hpp"

#include "qhttprequest.h"
#include "qhttpresponse.h"

using namespace Dissent::Anonymity;
using namespace Dissent::Applications;
using namespace Dissent::ClientServer;
using namespace Dissent::Connections;
using namespace Dissent::Crypto;
using namespace Dissent::Crypto::AbstractGroup;
using namespace Dissent::Crypto::BlogDrop;
using namespace Dissent::Identity;
using namespace Dissent::Messaging;
using namespace Dissent::Session;
using namespace Dissent::Transports;
using namespace Dissent::Utils;
using namespace Dissent::Web;

/**
 * There are a few services that send messages via the anonymity layer,
 * to provide for multiplexing of these services, we have hacked in a 
 * header of the form: [32-bit length][32-bit packet type][message]
 * The current packet types are:
 *  0 - Cleartext message (SendMessageService)
 *  1 - Web traffic (Tunnel)
 *
 * This is currently just a hack and we probably ought to develop a
 * better module system to enforce (assist in) moving the packets
 * around correctly.
 */

#endif
