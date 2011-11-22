#ifndef DISSENT_ANONYMITY_ROUND_H_GUARD
#define DISSENT_ANONYMITY_ROUND_H_GUARD

#include <stdexcept>

#include <QObject>

#include "../Connections/ConnectionTable.hpp"
#include "../Messaging/ISender.hpp"
#include "../Messaging/Source.hpp"
#include "../Messaging/RpcHandler.hpp"
#include "../Utils/StartStop.hpp"

#include "Group.hpp"
#include "GroupGenerator.hpp"
#include "GetDataCallback.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Connections;
    using namespace Dissent::Messaging;
    using namespace Dissent::Utils;
  }

  /**
   * Represents a single instance of a cryptographically secure anonymous exchange
   */
  class Round : public QObject, public StartStop, public Source,
      public ISender, public ISink {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param group_gen Generate groups for use during this round
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param round_id Unique round id (nonce)
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       * @param signing_key a signing key for the local node, matched to the
       * node in the group
       * @param get_data requests data to share during this session
       */
      Round(QSharedPointer<GroupGenerator> group_gen, const Id &local_id,
          const Id &session_id, const Id &round_id, const ConnectionTable &ct,
          RpcHandler &rpc, QSharedPointer<AsymmetricKey> signing_key,
          GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~Round() {}

      /**
       * Handle a data message from a remote peer
       * @param data The remote peers data
       * @param from The remote peer
       */
      virtual void HandleData(const QByteArray &data, ISender *from);

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
      inline const QString &GetStoppedReason() const { return _stopped_reason; }

      /**
       * Returns the Session Id
       */
      inline const Id &GetId() const { return _session_id; }

      /**
       * Returns whether or not there were any problems in the round
       */
      inline bool Successful() const { return _successful; }

      /**
       * Returns the local id
       */
      inline const Id &GetLocalId() const { return _local_id; }

      /**
       * Returns the round id
       */
      inline const Id &GetRoundId() const { return _round_id; }

      /**
       * Returns the group generator if subgroups are necessary
       */
      inline QSharedPointer<GroupGenerator> GetGroupGenerator() const { return _group_gen; }

      /**
       * Returns the group used in the round
       */
      inline const Group &GetGroup() const { return _group; }

      /**
       * Returns the list of bad nodes discovered in the round
       */
      inline virtual const QVector<int> &GetBadMembers() const { return _empty_list; }

      /**
       * Send is not implemented, it is here simply so we can reuse the Source
       * paradigm and have the session recognize which round produced the result
       */
      virtual void Send(const QByteArray &data);

      /**
       * Returns the data for the position specified.
       */
      QByteArray GetPlaintextData(int index);

      inline virtual QString ToString() const { return "Round"; }

    signals:
      /**
       * Emitted when the Round is closed for good or bad.
       */
      void Finished();

    protected:
      /**
       * Send a message to all group members
       * @param data Data to be sent to all peers
       */
      virtual void Broadcast(const QByteArray &data);

      /**
       * Send a message to a specific group member
       * @param data The message
       * @param id The Id of the remote peer
       */
      virtual void Send(const QByteArray &data, const Id &id);

      /**
       * If data is from a legitimate group member, it is processed
       * @param data Incoming data
       * @param id the remote peer sending the data
       */
      virtual void ProcessData(const QByteArray &data, const Id &id) = 0;

      /**
       * Returns the data to be sent during this round
       */
      inline const QPair<QByteArray, bool> GetData(int max) { return _get_data_cb(max); }

      /**
       * Returns the nodes signing key
       */
      inline const QSharedPointer<AsymmetricKey> GetSigningKey() { return _signing_key; }

      /**
       * Sets the received data for the specified peer, currently this API
       * supports only a single plaintext per peer, so this returns true if
       * this is the first time calling this function.
       * @param index the order the message was received / position in the
       * pseudonym range
       * @param data the received data
       */
      bool SetPlaintextData(int index, const QByteArray &data);

      /**
       * If data exists, this appends this new byte array to the remote peer,
       * otherwise it creates a new entry (like the SetPlaintextData does.
       * @param index the order the message was received / position in the
       * pseudonym range
       * @param data the received data
       */
      bool SetOrAppendPlaintextData(int index, const QByteArray &data);

      void SetSuccessful(bool successful) { _successful = successful; }

    private:
      QSharedPointer<GroupGenerator> _group_gen;
      const Group _group;
      const Id _local_id;
      const Id _session_id;
      const Id _round_id;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      QSharedPointer<AsymmetricKey> _signing_key;
      GetDataCallback &_get_data_cb;
      bool _successful;
      QString _stopped_reason;
      QVector<int> _empty_list;
      QHash<int, QByteArray> _data_received;

    private slots:
      /**
       * If the ConnectionTable has a disconnect, the round may need to react
       * @param con the Connection that disconnected
       * @param reason the reason it was disconnected
       */
      virtual void HandleDisconnect(Connection *con, const QString &reason);
  };

  typedef Round *(*CreateRound)(QSharedPointer<GroupGenerator> , const Id &,
      const Id &, const Id &, const ConnectionTable &, RpcHandler &,
      QSharedPointer<AsymmetricKey>, GetDataCallback &get_data_cb);
}
}

#endif
