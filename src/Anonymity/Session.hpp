#ifndef DISSENT_ANONYMITY_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SESSION_H_GUARD

#include <QHash>
#include <QQueue>

#include "Group.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  namespace {
    using namespace Dissent::Messaging;
    using namespace Dissent::Connections;
  }

  /**
   * Maintains a group which is actively participating in anonymous exchanges
   */
  class Session : public QObject, public Filter {
    Q_OBJECT

    public:
      typedef Round *(*CreateRound)(const Id &, const Group &,
          const ConnectionTable &, RpcHandler &, const Id &,
          const QByteArray &);

      /**
       * Constructor
       */
      Session(const Id &local_id, const Id &leader_id, const Group &group,
          ConnectionTable &ct, RpcHandler &rpc, const Id &session_id,
          CreateRound create_round, const QByteArray &default_data);

      /**
       * Deconstructor
       */
      ~Session();

      /**
       * Begin the Session
       */
      void Start();

      /**
       * Stop the Session, emits closed when all state has finished
       */
      void Stop();

      /**
       * From the SessionManager, pass in a ReceiveReady
       * @param request The request from a group member
       */
      void ReceivedReady(RpcRequest &request);

      /**
       * From the SessionManager, pass in incoming data
       * @param notification The message containing the data
       */
      void IncomingData(RpcRequest &notification);

      /**
       * From a client software, send a message anonymously
       */
      virtual void Send(const QByteArray &data);

      /**
       * Returns true if the peer is the leader for this session
       */
      inline bool IsLeader() { return _local_id == _leader_id; }

      /**
       * Returns the Session Id
       */
      inline const Id &GetId() const { return _session_id; }

      /**
       * Is the session still active?
       */
      inline bool Closed() { return _closed; }

    signals:
      /**
       * Signals that a round has completed.  The round will be deleted after
       * the signal has returned.
       * @param session this
       * @param round _current_round
       */
      void RoundFinished(Session *session, Round *round);

      /**
       * Signfies that the session has been closed / stopped
       * @param session this
       */
      void Closed(Session *session);

    protected:
      const Id _local_id;
      const Id _leader_id;
      const Group _group;
      const ConnectionTable &_ct;
      RpcHandler &_rpc;
      const Id _session_id;
      const QByteArray _default_data;

    private:
      /**
       * Checks to see if the leader has received all the Ready messsages and
       * broadcasts responses if it has.
       */
      bool LeaderReady();

      /**
       * Called to start the next Round
       */
      void NextRound();

      /**
       * Obtains a new round
       * @param data data to be transmitted
       */
      virtual Round *GetRound(const QByteArray &data);

      /**
       * Called when a Ready has been responded to by the leader.  Calls Start
       * on the current round.
       * @param response The response from the server (empty)
       */
      void Ready(RpcRequest &response);

      /**
       * Used by the leader to queue Ready requests.
       */
      QHash<Id, RpcRequest> _id_to_request;

      /**
       * Used by a client to store messages to be sent for future rounds
       */
      QQueue<QByteArray> _send_queue;

      Round *_current_round;
      bool _started;
      bool _closed;
      RpcMethod<Session> _ready;
      CreateRound _create_round;

    private slots:
      /**
       * Called when the current round has finished
       * @param round The round that finished (should be _current_round)
       */
      virtual void HandleRoundFinished(Round *round);

      /**
       * Called when a remote peer has disconnected from the session
       * @param con The connection that is disconnecting
       */
      virtual void HandleDisconnect(Connection *con, const QString &reason);
  };
}
}

#endif
