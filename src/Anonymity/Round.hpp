#ifndef DISSENT_ANONYMITY_ROUND_H_GUARD
#define DISSENT_ANONYMITY_ROUND_H_GUARD

#include <stdexcept>

#include <QObject>

#include "../Connections/ConnectionTable.hpp"
#include "../Messaging/ISender.hpp"
#include "../Messaging/Source.hpp"
#include "../Messaging/RpcHandler.hpp"

#include "Group.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Connections;
  }

  /**
   * Represents a single instance of a cryptographically secure anonymous exchange
   */
  class Round : public QObject, public Source, public ISender, public ISink {
    Q_OBJECT

    public:
      /**
       * Constructor 
       * @param group The anonymity group
       * @param local_id The local peers id
       * @param session_id Session this round represents
       * @param ct Connections to the anonymity group
       * @param rpc Rpc handler for sending messages
       */
      Round(const Group &group, const Id &local_id, const Id &session_id,
          const ConnectionTable &ct, RpcHandler &rpc);

      /**
       * Start the Round
       */
      virtual bool Start() = 0;

      /**
       * Handle a data message from a remote peer
       * @param data The remote peers data
       * @param from The remote peer
       */
      virtual void HandleData(const QByteArray &data, ISender *from);

      /**
       * Produces a string representation of the round
       */
      virtual QString ToString();

      /**
       * Close the round for no specific reason
       */
      bool Close();

      /**
       * Close the round with a specific reason
       * @param reason The specific reason
       */
      bool Close(const QString &reason);

      /**
       * Returns the reason the Round was closed, empty string if it is not closed
       */
      inline const QString &GetClosedReason() const { return _closed_reason; }

      /**
       * Returns whether or not the round has closed
       */
      inline bool Closed() const { return _closed; }

      /**
       * Returns the Session Id
       */
      inline const Id &GetId() const { return _session_id; }

      /**
       * Returns whether or not there were any problems in the round
       */
      inline bool Successful() const { return _successful; }

      /**
       * Returns the group used in the round
       */
      inline const Group &GetGroup() const { return _group; }

      /**
       * Returns the list of bad nodes discovered in the round
       */
      inline virtual const QVector<int> &GetBadMembers() { return _empty_list; }

      /**
       * Send is not implemented, it is here simply so we can reuse the Source
       * paradigm and have the session recognize which round produced the result
       */
      virtual void Send(const QByteArray &data);

    signals:
      /**
       * Emitted when the Round is closed for good or bad.
       * @param round The actual Round (this)
       */
      void Finished(Round *round);

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
       * The anonymity group
       */
      const Group _group;

      /**
       * The local peer's Id
       */
      const Id _local_id;

      /**
       * Whether or not the Round was successful
       */
      bool _successful;

    private:
      QString _closed_reason;
      const Id _session_id;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      bool _closed;
      QVector<int> _empty_list;

    private slots:
      /**
       * If the ConnectionTable has a disconnect, the round may need to react
       * @param con the Connection that disconnected
       * @param reason the reason it was disconnected
       */
      virtual void HandleDisconnect(Connection *con, const QString &reason);
  };
}
}

#endif
