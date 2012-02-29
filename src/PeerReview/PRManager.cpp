#include "PRManager.hpp"

#include "ReceiveEntry.hpp"
#include "SendEntry.hpp"

#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/CryptoFactory.hpp"
#include "Crypto/Hash.hpp"
#include "Crypto/Library.hpp"

#include "Utils/Serialization.hpp"

using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::CryptoFactory;
using Dissent::Crypto::Hash;
using Dissent::Crypto::Library;

namespace Dissent {
namespace PeerReview {
  PRManager::PRManager(const PrivateIdentity &ident, const Group &group) :
    _ident(ident),
    _group(group)
  {
  }

  bool PRManager::Acknowledge(uint record, QByteArray &binary_ack) const
  {
    if((uint) _log.Size() <= record) {
      qWarning() << "No matching entry:" << record;
      return false;
    }

    QSharedPointer<ReceiveEntry> rentry = _log.At(record).dynamicCast<ReceiveEntry>();
    if(rentry.isNull()) {
      qWarning() << "Entry is not a RECEIVE.";
      return false;
    }

    Acknowledgement ack(rentry);
    binary_ack = ack.Serialize();
    return true;
  }

  bool PRManager::HandleAcknowledgement(const QByteArray &binary_ack,
      const Id &src)
  {
    QSharedPointer<AsymmetricKey> key = _group.GetKey(src);
    if(key.isNull()) {
      qWarning() << "HandleAcknowledgement: Remote participant unknown:" << src.ToString();
      return false;
    }

    QSharedPointer<Entry> entry = ParseEntry(binary_ack);
    QSharedPointer<Acknowledgement> ack = entry.dynamicCast<Acknowledgement>();
    if(ack.isNull()) {
      qWarning() << "Not an acknowledgement.";
      return false;
    }

    uint record = ack->GetSentSequenceId();
    if((uint) _log.Size() <= record) {
      qWarning() << "No matching entry:" << record;
      return false;
    }

    if(!ack->VerifySend(_log.At(record), key)) {
      qWarning() << "Invalid ack.";
      return false;
    }

    return _acks.Insert(ack);
  }

  /*
  bool PRManager::Fault(uint record)
  {
    return true;
  }
  */

  bool PRManager::Receive(const QByteArray &packet, const Id &src,
      QByteArray &msg, uint &seq_id)
  {
    QSharedPointer<AsymmetricKey> key = _group.GetKey(src);
    if(key.isNull()) {
      qWarning() << "PRManager::Receive, No record of remote member:" << src.ToString();
      return false;
    }

    QSharedPointer<Entry> s_entry = ParseEntry(packet);

    QSharedPointer<SendEntry> send_entry = s_entry.dynamicCast<SendEntry>();
    if(send_entry.isNull()) {
      qWarning() << "Expected a send entry found something else.";
      return false;
    }

    if(send_entry->GetDestination() != _ident.GetLocalId()) {
      qWarning() << "Message directed to another member:" <<
        send_entry->GetDestination().ToString();
      return false;
    }

    if(!send_entry->Verify(key)) {
      qWarning() << "Signature does not match message from" << src.ToString();
      return false;
    }

    seq_id = _log.PreviousSequenceId() + 1;

    QSharedPointer<Entry> entry(
        new ReceiveEntry(seq_id, src,
          _log.PreviousHash(), send_entry));

    entry->Sign(_ident.GetSigningKey());

    if(!_log.AppendEntry(entry)) {
      qFatal("Attempted to append a ReceiveEntry and failed!");
    }

    msg = send_entry->GetMessage();
    return true;
  }

  bool PRManager::Send(const QByteArray &msg, const Id &dest,
      QByteArray &packet)
  {
    QSharedPointer<AsymmetricKey> key = _group.GetKey(dest);
    if(key.isNull()) {
      qWarning() << "PRManager::Send, No record of remote member:" << dest.ToString();
      return false;
    }

    QSharedPointer<Entry> entry(
        new SendEntry(_log.PreviousSequenceId() + 1,
          dest, _log.PreviousHash(), msg));

    entry->Sign(_ident.GetSigningKey());

    if(!_log.AppendEntry(entry)) {
      qFatal("Attempted to append a SendEntry and failed!");
    }

    packet = entry->Serialize();
    return true;
  }

  QByteArray PRManager::Serialize() const
  {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << _log.Serialize();
    stream << _acks;
    return data;
  }

  void ParseLogs(const QByteArray &data, EntryLog &log, AcknowledgementLog &ack_log)
  {
    QDataStream stream(data);
    QByteArray binary_log;

    stream >> binary_log;
    log = EntryLog::ParseLog(binary_log);

    stream >> binary_log;
    ack_log = AcknowledgementLog(binary_log);
  }
}
}
