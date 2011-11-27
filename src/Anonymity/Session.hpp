#ifndef DISSENT_ANONYMITY_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SESSION_H_GUARD

#include <QHash>
#include <QQueue>

#include "../Connections/Network.hpp"
#include "../Utils/StartStop.hpp"

#include "Group.hpp"
#include "GroupGenerator.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * Maintains a group which is actively participating in anonymous exchanges
   */
  class Session : public QObject, public Filter, public StartStop {
    Q_OBJECT

    public:
      /**
       * Constructor
       * @param group an ordered member of peers for the group
       * @param local_id the local node's ID
       * @param leader_id the Id of the leader
       * @param session_id Id for the session
       * @param network handles message sending
       * @param signing_key the local nodes private signing key, pointer NOT
       * @param create_round a callback for creating a secure round
       * @param group_generator generates a subgroup of the primary group for
       * use in the round
       */
      Session(const Group &group, const Id &local_id, const Id &leader_id,
          const Id &session_id, QSharedPointer<Network> network,
          CreateRound create_round, QSharedPointer<AsymmetricKey> signing_key, 
          CreateGroupGenerator group_generator = GroupGenerator::Create);

      /**
       * Deconstructor
       */
      virtual ~Session() {}

      /**
       * Starts the session
       */
      virtual bool Start();

      /**
       * Stops the session
       */
      virtual bool Stop();

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
       * Returns the current round
       */
      inline QSharedPointer<Round> GetCurrentRound() { return _current_round; }

      /**
       * Returns the Session / Round information
       */
      inline virtual QString ToString() const
      {
        return "Session: " + GetId().ToString() + "|" +
          (_current_round.isNull() ? "No current round" : 
          _current_round->ToString());
      }

      /**
       * Returns the underlying GroupGenerator
       */
      inline const GroupGenerator &GetGroupGenerator() { return *_generate_group; }

    signals:
      /**
       * Signals that a round has completed.  The round will be deleted after
       * the signal has returned.
       * @param round _current_round
       */
      void RoundFinished(QSharedPointer<Round> round);

      /**
       * Signfies that the session has been closed / stopped
       */
      void Stopping();

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
       * Retrieves data from the data waiting queue, returns the byte array
       * containing data and a bool which is true if there is more data
       * available.
       * @param max the maximum amount of data to retrieve
       */
      QPair<QByteArray, bool> GetData(int max);

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
      QByteArray _send_queue;

      const Group _group;
      const Id _local_id;
      const Id _leader_id;
      const Id _session_id;
      QSharedPointer<Network> _network;
      CreateRound _create_round;
      QSharedPointer<AsymmetricKey> _signing_key;
      QSharedPointer<GroupGenerator> _generate_group;

      bool _round_ready;
      QSharedPointer<Round> _current_round;
      RpcMethod<Session> _ready;
      GetDataMethod<Session> _get_data_cb;
      int _round_idx;

    private slots:
      /**
       * Called when the current round has finished
       */
      virtual void HandleRoundFinished();

      /**
       * Called when a remote peer has disconnected from the session
       */
      virtual void HandleDisconnect();
  };
}
}

#endif
