#ifndef DISSENT_ANONYMITY_ROUND_H_GUARD
#define DISSENT_ANONYMITY_ROUND_H_GUARD

#include <stdexcept>

#include <QObject>
#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Connections/Network.hpp"
#include "Identity/Group.hpp"
#include "Identity/Credentials.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/ISender.hpp"
#include "Messaging/SourceObject.hpp"
#include "Utils/StartStop.hpp"

namespace Dissent {
namespace Connections {
  class Connection;
}

namespace Crypto {
  class AsymmetricKey;
  class DiffieHellman;
}

namespace Messaging {
  class Request;
}

namespace Anonymity {
  /**
   * An anonymous exchange amongst peers of a static group.
   */
  class Round : public Messaging::SourceObject,
      public Utils::StartStop,
      public Messaging::ISender
  {
    Q_OBJECT

    public:
      typedef Connections::Connection Connection;
      typedef Connections::Id Id;
      typedef Connections::Network Network;
      typedef Crypto::AsymmetricKey AsymmetricKey;
      typedef Crypto::DiffieHellman DiffieHellman;
      typedef Identity::Credentials Credentials;
      typedef Identity::Group Group;
      typedef Identity::GroupContainer GroupContainer;
      typedef Messaging::GetDataCallback GetDataCallback;
      typedef Messaging::Request Request;

      /**
       * Constructor
       * @param group Group used during this round
       * @param creds the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       */
      explicit Round(const Group &group, const Credentials &creds,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~Round() {}

      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingData(const Request &notification);

      /**
       * Close the round for no specific reason
       */
      virtual bool Stop();

      /**
       * Stop the round with a specific reason
       * @param reason The specific reason
       */
      bool Stop(const QString &reason);

      /**
       * Returns the reason the Round was closed, empty string if it is not closed
       */
      inline const QString &GetStoppedReason() const
      {
        return _stopped_reason;
      }

      /**
       * Returns whether or not there were any problems in the round
       */
      inline bool Successful() const { return _successful; }

      /**
       * Returns the local id
       */
      inline const Id &GetLocalId() const { return _creds.GetLocalId(); }

      /**
       * Returns the round id
       */
      inline const Id &GetRoundId() const { return _round_id; }

      /**
       * Returns the group used in the round
       */
      inline const Group &GetGroup() const { return _group; }

      /**
       * Returns the list of bad nodes discovered in the round
       */
      inline virtual const QVector<int> &GetBadMembers() const
      {
        return _empty_list;
      }

      /**
       * Send is not implemented, it is here simply so we can reuse the Source
       * paradigm and have the session recognize which round produced the result
       */
      virtual void Send(const QByteArray &data);

      /**
       * If the ConnectionTable has a disconnect, the round may need to react
       * @param id the peer that was disconnected
       */
      virtual void HandleDisconnect(const Id &id);

      inline virtual QString ToString() const { return "Round"; }

      /**
       * Notifies the round of a new peer wanting to join.  Default behavior is
       * to do nothing and wait for the next round.
       */
      virtual void PeerJoined() {}

      /**
       * Returns true if the protocol supports nodes that have left the round
       * to rejoin.
       */
      virtual bool SupportsRejoins() { return false; }

      /**
       * Was the round interrupted?  Should the leader interrupt others.
       */
      bool Interrupted() { return _interrupted; }

      /**
       * Round interrupted, leader should interrupt others.
       */
      void SetInterrupted() { _interrupted = true; }

      inline QSharedPointer<Round> GetSharedPointer()
      {
        return _shared.toStrongRef();
      }

      void SetSharedPointer(const QSharedPointer<Round> &shared)
      {
        _shared = shared.toWeakRef();
      }

    signals:
      /**
       * Emitted when the Round is closed for good or bad.
       */
      void Finished();

    protected:
      /**
       * If data is from a legitimate group member, it is processed
       * @param data Incoming data
       * @param id the remote peer sending the data
       */
      virtual void ProcessData(const Id &id, const QByteArray &data) = 0;

      /**
       * Verifies that the provided data has a signature block and is properly
       * signed, returning the data block via msg
       * @param from the signing peers id
       * @param data the data + signature blocks
       * @param msg the data block
       */
      bool Verify(const Id &from, const QByteArray &data, QByteArray &msg);

      /**
       * Signs and encrypts a message before broadcasting
       * @param data the message to broadcast
       */
      virtual inline void VerifiableBroadcast(const QByteArray &data)
      {
        QByteArray msg = data + GetSigningKey()->Sign(data);
        GetNetwork()->Broadcast(msg);
      }

      /**
       * Signs and encrypts a message before sending it to a sepecific peer
       * @param to the peer to send it to
       * @param data the message to send
       */
      virtual inline void VerifiableSend(const Id &to, const QByteArray &data)
      {
        QByteArray msg = data + GetSigningKey()->Sign(data);
        GetNetwork()->Send(to, msg);
      }

      /**
       * Returns the data to be sent during this round
       */
      inline const QPair<QByteArray, bool> GetData(int max)
      {
        return _get_data_cb(max);
      }

      /**
       * Returns the nodes signing key
       */
      inline QSharedPointer<AsymmetricKey> GetSigningKey() const
      {
        return _creds.GetSigningKey();
      }

      /**
       * Returns the local credentials
       */
      inline const Credentials &GetCredentials() const { return _creds; }

      /**
       * Returns the DiffieHellman key
       */
      inline QSharedPointer<DiffieHellman> GetDhKey() const
      {
        return _creds.GetDhKey();
      }

      void SetSuccessful(bool successful) { _successful = successful; }

      /**
       * Returns the underlyign network
       */
      QSharedPointer<Network> &GetNetwork() { return _network; }

    private:
      const Group _group;
      const Credentials _creds;
      const Id _round_id;
      QSharedPointer<Network> _network;
      GetDataCallback &_get_data_cb;
      bool _successful;
      QString _stopped_reason;
      QVector<int> _empty_list;
      bool _interrupted;
      QWeakPointer<Round> _shared;
  };

  typedef QSharedPointer<Round> (*CreateRound)(const Round::Group &,
      const Round::Credentials &, const Connections::Id &,
      QSharedPointer<Connections::Network>,
      Messaging::GetDataCallback &get_data_cb);

  template <typename T> QSharedPointer<Round> TCreateRound(
      const Round::Group &group, const Round::Credentials &creds,
      const Connections::Id &round_id,
      QSharedPointer<Connections::Network> network,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<T> round(new T(group, creds, round_id, network, get_data));
    round->SetSharedPointer(round);
    return round;
  }
}
}

#endif
