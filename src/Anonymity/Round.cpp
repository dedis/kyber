#include "Connections/Connection.hpp"
#include "Messaging/Request.hpp"

#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  Round::Round(const Group &group, const Credentials &creds, const Id &round_id,
      QSharedPointer<Network> network, GetDataCallback &get_data) :
    _group(group),
    _creds(creds),
    _round_id(round_id),
    _network(network),
    _get_data_cb(get_data),
    _successful(false),
    _interrupted(false)
  {
  }

  bool Round::Stop()
  {
    return Stop("Explicitly closed");
  }

  bool Round::Stop(const QString &reason)
  {
    if(!StartStop::Stop()) {
      return false;
    }

    _stopped_reason = reason;
    emit Finished();
    return true;
  }

  void Round::IncomingData(const Request &notification)
  {
    if(Stopped()) {
      qWarning() << "Received a message on a closed session:" << ToString();
      return;
    }
      
    QSharedPointer<Connections::IOverlaySender> sender =
      notification.GetFrom().dynamicCast<Connections::IOverlaySender>();

    if(!sender) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    const Id &id = sender->GetRemoteId();
    if(!_group.Contains(id)) {
      qDebug() << ToString() << " received wayward message from: " <<
        notification.GetFrom()->ToString();
      return;
    }

    ProcessData(id, notification.GetData().toHash().value("data").toByteArray());
  }

  bool Round::Verify(const Id &from, const QByteArray &data, QByteArray &msg)
  {
    QSharedPointer<AsymmetricKey> key = GetGroup().GetKey(from);
    if(key.isNull()) {
      qDebug() << "Received malsigned data block, no such peer";
      return false;
    }

    int sig_size = key->GetKeySize() / 8;
    if(data.size() < sig_size) {
      qDebug() << "Received malsigned data block, not enough data blocks." <<
       "Expected at least:" << sig_size << "got" << data.size();
      return false;
    }

    msg = data.left(data.size() - sig_size);
    QByteArray sig = QByteArray::fromRawData(data.data() + msg.size(), sig_size);
    return key->Verify(msg, sig);
  }

  void Round::HandleDisconnect(const Id &id)
  {
    if(_group.Contains(id)) {
      SetInterrupted();
      Stop(QString(id.ToString() + " disconnected"));
    }
  }

  void Round::Send(const QByteArray &)
  {
    throw std::logic_error("Not implemented");
  }
}
}
