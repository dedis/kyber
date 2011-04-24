/* libdissent/network.cc
   Network layer (w/ signing and logging) for dissent protocol.

   Author: Shu-Chun Weng <scweng _AT_ cs .DOT. yale *DOT* edu>
 */
/* ====================================================================
 * Dissent: Accountable Group Anonymity
 * Copyright (c) 2010 Yale University.
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to
 *
 *   Free Software Foundation, Inc.,
 *   51 Franklin Street, Fifth Floor,
 *   Boston, MA  02110-1301  USA
 */

#include "network.hpp"

#include <QtGlobal>
#include <QAbstractSocket>
#include <QHostAddress>
#include <QSet>
#include <QSignalMapper>
#include <QTcpServer>
#include <QTcpSocket>
#include <QTimer>
#include <QVariant>
#include <cstdio>

#include "QByteArrayUtil.hpp"
#include "config.hpp"
#include "crypto.hpp"
#include "random_util.hpp"

namespace Dissent{
const int Network::MulticastNodeId;

Network::Network(Configuration* config)
    : _config(config),
      _isReady(false),
      _inReceivingPhase(false),
      _nonce(-1){
    _prepare = new NetworkPrepare(config, &_server, &_clients);
    connect(_prepare, SIGNAL(networkReady()),
            this, SLOT(NetworkReady()));

    _prepare->DoPrepare(
            QHostAddress::Any,
            config->nodes[config->my_node_id].port);
}

void Network::ResetSession(qint32 nonce){
    _nonce = nonce;
    ClearLog();
    // clear accumulative hash
}

int Network::Send(int node_id, const QByteArray& data){
    QTcpSocket* socket = _clients[node_id];
    Q_ASSERT(socket);
    Q_ASSERT(socket->state() == QAbstractSocket::ConnectedState);

    QByteArray plaintext, sig;
    PrepareMessage(LogEntry::SEND, data, &plaintext, &sig);
    int w_count = socket->write(plaintext);
    w_count += socket->write(sig);
    Q_ASSERT(w_count == plaintext.size() + sig.size());

    //printf("To %d: %s\n", node_id, (char*) plaintext.toHex().data());
    //printf("Sig:  %s\n", (char*) sig.toHex().data());
    //printf("-> %s:%d\n",
    //       (char*) socket->peerAddress().toString().toUtf8().data(),
    //       socket->peerPort());

    LogEntry log = { LogEntry::SEND, node_id, data, sig, true };
    _log.push_back(log);
    return w_count;
}

int Network::Broadcast(const QByteArray& data){
    QByteArray plaintext, sig;
    PrepareMessage(LogEntry::BROADCAST_SEND, data, &plaintext, &sig);

    foreach(const NodeInfo& node, _config->nodes)
        if(node.node_id != _config->my_node_id && !node.excluded){
            QTcpSocket* socket = _clients[node.node_id];
            Q_ASSERT_X(socket, "Network::Broadcast",
                       (const char*) QString("socket[%1] = null")
                       .arg(node.node_id).toUtf8().data());
            Q_ASSERT_X(socket->state() == QAbstractSocket::ConnectedState,
                       "Network::Broadcast",
                       (const char*) QString("socket[%1] wrong state")
                       .arg(node.node_id).toUtf8().data());
            int w_count = socket->write(plaintext);
            w_count += socket->write(sig);
            Q_ASSERT(w_count == plaintext.size() + sig.size());
        }

    LogEntry log = { LogEntry::BROADCAST_SEND, -1, data, sig, true };
    _log.push_back(log);
    return plaintext.size() + sig.size();
}

int Network::MulticastXor(const QByteArray& data){
    Q_ASSERT(_multicast == 0);
    const int collector_node_id = _config->topology.front().node_id;
    if(collector_node_id == _config->my_node_id){
printf("I'm multicast leader\n");
        _multicast = new MulticastXorProcessor(this, _config->num_nodes, data);
        connect(_multicast, SIGNAL(multicastReady(QByteArray)),
                this, SLOT(MulticastReady(QByteArray)));
        connect(_multicast, SIGNAL(multicastError(int, QString)),
                this, SLOT(MulticastError(int, QString)));
        while(_multicastBuffer.size()){
            Q_ASSERT(_multicastBuffer.front().status == Buffer::DONE);
            const LogEntry& entry = _multicastBuffer.front().entry;
            _multicast->EnterMessage(entry.node_id, entry.data);
            _multicastBuffer.pop_front();
        }
        return data.size();
    }

    QTcpSocket* socket = _clients[collector_node_id];
    Q_ASSERT(socket);
    Q_ASSERT(socket->state() == QAbstractSocket::ConnectedState);

    QByteArray plaintext, sig;
    PrepareMessage(LogEntry::MULTICAST, data, &plaintext, &sig);
    int w_count = socket->write(plaintext);
    w_count += socket->write(sig);
    Q_ASSERT(w_count == plaintext.size() + sig.size());

    LogEntry log = { LogEntry::MULTICAST, collector_node_id,
                     data, sig, true };
    _log.push_back(log);
    return w_count;
}

int Network::Read(int node_id, QByteArray* data){
    QList<Buffer>& buffer = _buffers[node_id];
    while(buffer.size() > 0 && buffer.front().status == Buffer::DONE){
        const Buffer& buf = buffer.front();
        const bool valid = buf.entry.valid;
        *data = buf.entry.data;
        _log.push_back(buf.entry);
        buffer.pop_front();  // now we can drop it from buffer
        if(valid)
            return 1;
    }
    return 0;
}

void Network::PrepareMessage(int type, const QByteArray& data,
                             QByteArray* message, QByteArray* sig){
    // Updates of this function should pair up with updates of
    // ValidateLogEntry() and ClientHasReadyRead()
    message->clear();
    QByteArrayUtil::AppendInt(type, message);
    QByteArrayUtil::AppendInt(_nonce, message);
    // TODO(scw): how to accumulate hash?
    message->append(data);

    bool r = Crypto::GetInstance()->Sign(&_config->identity_sk,
                                         *message, sig);
    Q_ASSERT_X(r, "Network::PrepareMessage", "message signing failed");

    int message_length = message->size();
    QByteArrayUtil::PrependInt(sig->size(), message);
    QByteArrayUtil::PrependInt(message_length, message);
}

bool Network::ValidateLogEntry(LogEntry* entry){
    // Updates of this function should pair up with updates of
    // PrepareMessage() and ClientHasReadyRead()
    bool valid_sig = Crypto::GetInstance()->Verify(
            &_config->nodes[entry->node_id].identity_pk,
            entry->data,
            entry->signature);
    entry->dir = static_cast<LogEntry::Dir>(
            QByteArrayUtil::ExtractInt(true, &entry->data));
    int nonce =
            QByteArrayUtil::ExtractInt(true, &entry->data);
    bool valid_dir = (entry->dir == LogEntry::SEND ||
                      entry->dir == LogEntry::BROADCAST_SEND ||
                      entry->dir == LogEntry::MULTICAST ||
                      entry->dir == LogEntry::MULTICAST_FINAL);
    bool valid_nonce = (nonce == _nonce);
    if(entry->dir == LogEntry::SEND)
        entry->dir = LogEntry::RECV;
    else if(entry->dir == LogEntry::BROADCAST_SEND)
        entry->dir = LogEntry::BROADCAST_RECV;

    return entry->valid = (valid_sig && valid_dir && valid_nonce);
}

void Network::ClientHasReadyRead(int node_id){
    // Updates of this function should pair up with updates of
    // PrepareMessage() and ValidateLogEntry()
    if(_config->nodes[node_id].excluded)
        return;
    QMap<int, QTcpSocket*>::const_iterator it = _clients.constFind(node_id);
    if(it == _clients.constEnd())
        qFatal("Unknown client notifying ready");
    QTcpSocket* socket = it.value();

    QList<Buffer>& buffer = _buffers[node_id];
    if(buffer.size() == 0 || buffer.back().status == Buffer::DONE)
        buffer.push_back(Buffer());
    Buffer& buf = buffer.back();
    QByteArray byte_array;
    switch(buf.status){
        case Buffer::NEW:
            if(socket->bytesAvailable() < QByteArrayUtil::IntegerSize * 2)
                break;
            byte_array = socket->read(QByteArrayUtil::IntegerSize * 2);
            buf.data_len = QByteArrayUtil::ExtractInt(true, &byte_array);
            buf.sig_len = QByteArrayUtil::ExtractInt(true, &byte_array);
            buf.status = Buffer::HAS_SIZE;
            // fall through

        case Buffer::HAS_SIZE:
            if(socket->bytesAvailable() < buf.data_len)
                break;
            buf.entry.data = socket->read(buf.data_len);
            buf.status = Buffer::DATA_DONE;
            // fall through
            // fprintf(stderr, "<%d> %s\n", node_id, (char*) buf.entry.data.toHex().data());

        case Buffer::DATA_DONE:
            if(socket->bytesAvailable() < buf.sig_len)
                break;
            buf.entry.signature = socket->read(buf.sig_len);
            buf.entry.node_id = node_id;
            buf.status = Buffer::DONE;
            // fprintf(stderr, "s%d> %s\n", node_id, (char*) buf.entry.signature.toHex().data());
            if(!ValidateLogEntry(&buf.entry)){
                fprintf(stderr,
                        "Package from node %d cannot be validated\n"
                        ">> %s\n", node_id, buf.entry.data.toHex().data());
                break;
            }else if(buf.entry.dir == LogEntry::MULTICAST){
                if(_config->topology.front().node_id !=
                        _config->my_node_id){
                    fprintf(stderr,
                            "multicast message from node %d to non-leader\n",
                            node_id);
                    break;
                }

                if(!_multicast){
                    _multicastBuffer.push_back(buf);
                }else{
                    Q_ASSERT_X(_multicastBuffer.size() == 0,
                               "Network::ClientHasReadyRead",
                               "multicast and multicast buffer shouldn't"
                               " coexist");
                    _multicast->EnterMessage(node_id, buf.entry.data);
                }

                // No consumer, log it ourselves and pop off
                _log.push_back(buf.entry);
                buffer.pop_back();
                break;
            }else if(buf.entry.dir == LogEntry::MULTICAST_FINAL){
                node_id = MulticastNodeId;
                _buffers[MulticastNodeId].push_back(buf);
                buffer.pop_back();
            }
            
            if(_inReceivingPhase){
                emit readyRead(node_id);
            }
            break;

        default:
            qFatal("Invalid buf.status: %d\n", buf.status);
            break;
    }

    // XXX(scw): change tail recursion to loop
    if(socket->bytesAvailable() > 0)
        ClientHasReadyRead(node_id);
}

void Network::NetworkReady(){
    // Or keep it so that hosts can reconnect if connection dropped?
    delete _prepare; _prepare = 0;

    _signalMapper = new QSignalMapper(this);
    connect(_signalMapper, SIGNAL(mapped(int)),
            this, SLOT(ClientHasReadyRead(int)));

    _clientNodeId.clear();
    for(QMap<int, QTcpSocket*>::const_iterator it =  _clients.constBegin();
        it != _clients.constEnd(); ++it){
        _buffers.insert(it.key(), QList<Buffer>());
        _clientNodeId.insert(it.value(), it.key());
        _signalMapper->setMapping(it.value(), it.key());
        connect(it.value(), SIGNAL(readyRead()),
                _signalMapper, SLOT(map()));
        ClientHasReadyRead(it.key());
    }
    _buffers.insert(MulticastNodeId, QList<Buffer>());

    _isReady = true;
    emit networkReady();
}

void Network::MulticastReady(QByteArray data){
    delete _multicast;
    _multicast = 0;

    QByteArray plaintext, sig;
    PrepareMessage(LogEntry::MULTICAST_FINAL, data, &plaintext, &sig);

    foreach(const NodeInfo& node, _config->nodes)
        if(node.node_id != _config->my_node_id && !node.excluded){
            QTcpSocket* socket = _clients[node.node_id];
            Q_ASSERT_X(socket, "Network::MulticastReady",
                       (const char*) QString("socket[%1] = null")
                       .arg(node.node_id).toUtf8().data());
            Q_ASSERT_X(socket->state() == QAbstractSocket::ConnectedState,
                       "Network::MulticastReady",
                       (const char*) QString("socket[%1] wrong state")
                       .arg(node.node_id).toUtf8().data());
            int w_count = socket->write(plaintext);
            w_count += socket->write(sig);
            Q_ASSERT(w_count == plaintext.size() + sig.size());
        }

    LogEntry entry = { LogEntry::MULTICAST_FINAL, -1, data, sig, true };
    Buffer buffer;
    buffer.status = Buffer::DONE;
    buffer.entry = entry;
    _buffers[MulticastNodeId].push_back(buffer);
    if(_isReady)
        emit readyRead(MulticastNodeId);
}

void Network::MulticastError(int node_id, const QString& reason){
    emit inputError(node_id, reason);
}

void Network::StartIncomingNetwork(){
    if(_inReceivingPhase)
        return;
    // fprintf(stderr, "starting incoming network\n");

    _inReceivingPhase = true;
    for(QMap<int, QList<Buffer> >::const_iterator it = _buffers.constBegin();
        it != _buffers.constEnd(); ++it){
        // fprintf(stderr, "node %d: size = %d\n", it.key(), it.value().size());
        if(it.value().size() > 0 && it.value().front().status == Buffer::DONE){
            // fprintf(stderr, "node %d readyRead\n", it.key());
            emit readyRead(it.key());
        }
    }
}

void Network::StopIncomingNetwork(){
    _inReceivingPhase = false;
}

const char* const NetworkPrepare::ChallengePropertyName =
    "NetworkPrepareChallenge";
const char* const NetworkPrepare::NodeIdPropertyName =
    "NetworkPrepareNodeId";
const char* const NetworkPrepare::AnswerLengthPropertyName =
    "NetworkPrepareAnswerLength";
const int NetworkPrepare::ChallengeLength = 64;  // SHA-1 uses 512-bit blocks

NetworkPrepare::NetworkPrepare(Configuration* config,
                               QTcpServer* server,
                               QMap<int, QTcpSocket*>* sockets)
    : _config(config), _server(server), _sockets(sockets) {}

void NetworkPrepare::DoPrepare(const QHostAddress& address, quint16 port){
    connect(_server, SIGNAL(newConnection()),
            this, SLOT(NewConnection()));
    bool r = _server->listen(address, port);
    // fprintf(stderr, "%s:%d: %s\n",
    //        address.toString().toUtf8().data(), port,
    //        r ? "true" : "false");
    Q_ASSERT_X(r, "Network::Network(Configuration*)",
               _server->errorString().toUtf8().data());

    _incomeSignalMapper = new QSignalMapper(this);
    connect(_incomeSignalMapper, SIGNAL(mapped(QObject*)),
            this, SLOT(ReadNodeId(QObject*)));
    _answerSignalMapper = new QSignalMapper(this);
    connect(_answerSignalMapper, SIGNAL(mapped(QObject*)),
            this, SLOT(ReadChallengeAnswer(QObject*)));

    _connectSignalMapper = new QSignalMapper(this);
    _errorSignalMapper = new QSignalMapper(this);
    _challengeSignalMapper = new QSignalMapper(this);
    connect(_challengeSignalMapper, SIGNAL(mapped(QObject*)),
            this, SLOT(ReadChallenge(QObject*)));

    QTimer::singleShot(1000, this, SLOT(TryConnect()));
}

void NetworkPrepare::AddSocket(int node_id, QTcpSocket* socket){
    _sockets->insert(node_id, socket);
    if(_sockets->size() < _config->num_nodes - 1)
        return;

    for(QMap<int, NodeInfo>::const_iterator it = _config->nodes.constBegin();
        it != _config->nodes.constEnd(); ++it){
        if(it.key() == _config->my_node_id)
            continue;
        QMap<int, QTcpSocket*>::const_iterator jt =
            _sockets->constFind(it.key());
        if(jt == _sockets->constEnd())
            return;
        QTcpSocket* s = *jt;
        if(!s->isValid() || s->state() != QAbstractSocket::ConnectedState)
            return;
    }

    disconnect(_server, SIGNAL(newConnection()),
               this, SLOT(NewConnection()));
    emit networkReady();
}

void NetworkPrepare::NewConnection(){
    QTcpSocket* socket = _server->nextPendingConnection();

    char challenge[ChallengeLength];
    Random::GetInstance()->GetBlock(sizeof(challenge), challenge);
    QByteArray ba(challenge, sizeof(challenge));
    socket->setProperty(ChallengePropertyName, ba);

    _incomeSignalMapper->setMapping(socket, socket);
    connect(socket, SIGNAL(readyRead()), _incomeSignalMapper, SLOT(map()));

    socket->write(ba);
}

void NetworkPrepare::ReadNodeId(QObject* o){
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(o);
    Q_ASSERT(socket);

    if(socket->bytesAvailable() < QByteArrayUtil::IntegerSize * 2)
        return;

    QByteArray data = socket->read(8);
    int node_id = QByteArrayUtil::ExtractInt(true, &data);
    int answer_length = QByteArrayUtil::ExtractInt(true, &data);

    if(socket->peerAddress() != QHostAddress(_config->nodes[node_id].addr)){
        // XXX(scw): wrong host message
        fprintf(stderr, "peer %d expect from %s but from %s\n",
               node_id,
               (char*) _config->nodes[node_id].addr.toUtf8().data(),
               (char*) socket->peerAddress().toString().toUtf8().data());
        socket->disconnectFromHost();
        delete socket;
        return;
    }

    socket->setProperty(NodeIdPropertyName, node_id);
    socket->setProperty(AnswerLengthPropertyName, answer_length);
    _answerSignalMapper->setMapping(socket, socket);

    disconnect(socket, SIGNAL(readyRead()), _incomeSignalMapper, SLOT(map()));
    connect(socket, SIGNAL(readyRead()), _answerSignalMapper, SLOT(map()));
    ReadChallengeAnswer(o);
}

void NetworkPrepare::ReadChallengeAnswer(QObject* o){
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(o);
    Q_ASSERT(socket);

    bool ok = false;
    int answer_length =
        socket->property(AnswerLengthPropertyName).toInt(&ok);
    Q_ASSERT_X(ok, "NetworkPrepare::ReadChallengeAnswer",
                   "anser length property not an integer");

    if(socket->bytesAvailable() < answer_length)
        return;

    int node_id = socket->property(NodeIdPropertyName).toInt(&ok);
    Q_ASSERT_X(ok, "NetworkPrepare::ReadChallengeAnswer",
                   "node id property not an integer");

    QByteArray challenge =
        socket->property(ChallengePropertyName).toByteArray();
    Q_ASSERT(challenge.size() == ChallengeLength);

    QByteArray answer = socket->read(answer_length);
    if(!Crypto::GetInstance()->Verify(
                &_config->nodes[node_id].identity_pk,
                challenge,
                answer)){
        // XXX(scw): challenge failed message
        fprintf(stderr, "node %d challenge failed\n", node_id);
        socket->disconnectFromHost();
        delete socket;
        return;
    }

    socket->setProperty(NodeIdPropertyName, QVariant());
    socket->setProperty(AnswerLengthPropertyName, QVariant());
    socket->setProperty(ChallengePropertyName, QVariant());
    disconnect(socket, SIGNAL(readyRead()),
               _answerSignalMapper, SLOT(map()));

    AddSocket(node_id, socket);
}

void NetworkPrepare::TryConnect(){
    connect(_connectSignalMapper, SIGNAL(mapped(QObject*)),
            this, SLOT(Connected(QObject*)));
    connect(_errorSignalMapper, SIGNAL(mapped(QObject*)),
            this, SLOT(ConnectError(QObject*)));

    foreach(const NodeInfo& node, _config->nodes){
        if(node.node_id >= _config->my_node_id)
            continue;

        QTcpSocket* socket = new QTcpSocket(_server);
        connect(socket, SIGNAL(connected()),
                _connectSignalMapper, SLOT(map()));
        connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
                _errorSignalMapper, SLOT(map()));
        _connectSignalMapper->setMapping(socket, socket);
        _errorSignalMapper->setMapping(socket, socket);
        socket->setProperty(NodeIdPropertyName, node.node_id);
        socket->connectToHost(node.addr, node.port);
    }
}

void NetworkPrepare::Connected(QObject* o){
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(o);
    Q_ASSERT(socket);

    disconnect(socket, SIGNAL(connected()),
               _connectSignalMapper, SLOT(map()));
    disconnect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
               _errorSignalMapper, SLOT(map()));

    _challengeSignalMapper->setMapping(socket, socket);
    connect(socket, SIGNAL(readyRead()),
            _challengeSignalMapper, SLOT(map()));
    ReadChallenge(o);
}

void NetworkPrepare::ConnectError(QObject* o){
    // XXX(scw): error message? retry count? wait before retry?
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(o);
    Q_ASSERT(socket);

    bool ok = false;
    int node_id = socket->property(NodeIdPropertyName).toInt(&ok);
    Q_ASSERT_X(ok, "NetworkPrepare::ConnectError",
                   "node id property not an integer");

    const NodeInfo& node = _config->nodes[node_id];
    socket->connectToHost(node.addr, node.port);
}

void NetworkPrepare::ReadChallenge(QObject* o){
    QTcpSocket* socket = qobject_cast<QTcpSocket*>(o);
    Q_ASSERT(socket);

    if(socket->bytesAvailable() < ChallengeLength)
        return;

    QByteArray challenge = socket->read(ChallengeLength);
    QByteArray answer;
    bool r = Crypto::GetInstance()->Sign(
            &_config->identity_sk, challenge, &answer);
    Q_ASSERT_X(r, "NetworkPrepare::ReadChallenge",
                  "challeng signing failed");
    QByteArrayUtil::PrependInt(answer.size(), &answer);
    QByteArrayUtil::PrependInt(_config->my_node_id, &answer);
    socket->write(answer);

    bool ok = false;
    int node_id = socket->property(NodeIdPropertyName).toInt(&ok);
    Q_ASSERT_X(ok, "NetworkPrepare::ConnectError",
                   "node id property not an integer");

    socket->setProperty(NodeIdPropertyName, QVariant());
    disconnect(socket, SIGNAL(readyRead()),
               _challengeSignalMapper, SLOT(map()));

    AddSocket(node_id, socket);
}

MulticastXorProcessor::MulticastXorProcessor(
        Network* network, int num_nodes, const QByteArray& self_data)
    : QObject(network), _numNodes(num_nodes), _data(self_data){}

void MulticastXorProcessor::EnterMessage(
        int node_id, const QByteArray& data){
    if(_received.contains(node_id)){
        emit multicastError(node_id, "Multiple message from the same node");
        return;
    }

    char* p_d = _data.data();
    const char* p_s = data.constData();
    char* p_end = p_d + _data.size();
    for(; p_d < p_end; ++p_d, ++p_s)
        *p_d ^= *p_s;

    _received.insert(node_id);
    if(_received.size() == _numNodes - 1)
        emit multicastReady(_data);
}
}
// -*- vim:sw=4:expandtab:cindent:
