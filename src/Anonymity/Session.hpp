#ifndef DISSENT_ANONYMITY_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SESSION_H_GUARD

#include <QHash>
#include <QObject>
#include <QQueue>
#include <QSet>

#include "Connections/Id.hpp"
#include "Messaging/Filter.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/RpcMethod.hpp"
#include "Utils/StartStopSlots.hpp"
#include "Utils/TimerEvent.hpp"

#include "Credentials.hpp"
#include "Group.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Connections {
  class Connection;
  class Network;
}

namespace Crypto {
  class AsymmetricKey;
}

namespace Messaging {
  class RpcRequest;
}

namespace Anonymity {
  /**
   * Maintains a (variable) set of peers (group) which is actively
   * participating in anonymous exchanges (rounds).
   */
  class Session : public Dissent::Utils::StartStopSlots,
                    public Dissent::Messaging::Filter
  {
    Q_OBJECT

    public:
      typedef Dissent::Connections::Connection Connection;
      typedef Dissent::Connections::Id Id;
      typedef Dissent::Connections::Network Network;
      typedef Dissent::Crypto::AsymmetricKey AsymmetricKey;
      typedef Dissent::Messaging::RpcRequest RpcRequest;
      typedef Dissent::Messaging::RpcMethod<Session> RpcMethod;
      typedef Dissent::Messaging::GetDataMethod<Session> GetDataCallback;

      /**
       * Constructor
       * @param group an ordered member of peers for the group
       * @param creds the local nodes credentials
       * @param session_id Id for the session
       * @param network handles message sending
       * @param create_round a callback for creating a secure round
       */
      explicit Session(const Group &group, const Credentials &creds,
          const Id &session_id, QSharedPointer<Network> network,
          CreateRound create_round);

      /**
       * Deconstructor
       */
      virtual ~Session();

      /**
       * From the SessionManager, pass in a ReceivedRegister
       * @param request The request from a group member
       */
      void ReceivedRegister(RpcRequest &request);

      /**
       * From the SessionManager, pass in a ReceiveReady
       * @param request The request from the leader
       */
      void ReceivedPrepare(RpcRequest &request);

      /**
       * From the SessionManager, pass in a Begin message from the Session
       * leader to call start on the round
       * @param notification The notification from the leader
       */
      void ReceivedBegin(RpcRequest &notification);

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
      inline bool IsLeader() const { return _creds.GetLocalId() == _group.GetLeader(); }

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
       * Returns the group being used in this session
       */
      inline const Group &GetGroup() const { return _group; }

      /**
       * Get the set of bad group members
       */
      inline const QSet<Id> GetBadMembers() const { return _bad_members; }

      static const int MinimumRoundSize = 3;

      static const int PeerJoinDelay = 10000;

    signals:
      /**
       * Signals that a round is beginning.
       * @param round _current_round
       */
      void RoundStarting(QSharedPointer<Round> round);

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

    protected:
      /**
       * Called when the session is started
       */
      virtual void OnStart();

      /**
       * Called when the session is stopped
       */
      virtual void OnStop();

    private:
      /**
       * Called upon starting to register this peer with the leader
       * @param unused
       */
      void Register(const int&);

      /**
       * Called upon registration / round finished to start a new round
       * @param unused
       */
      void CheckRegistration(const int&);

      /**
       * Contains acknowledgement from the registration request
       * @param response the response may be positive or negative
       */
      void Registered(RpcRequest &response);

      /**
       */
      void Prepared(RpcRequest &response);

      /**
       * Checks to see if the leader has received all the Ready messsages and
       * broadcasts responses if it has.
       */
      bool SendPrepare();

      /**
       * Ensures that the group policy is being maintained
       */
      bool CheckGroup();

      /**
       * Called to start the next Round
       */
      void NextRound(const Id &round_id);

      /**
       * Retrieves data from the data waiting queue, returns the byte array
       * containing data and a bool which is true if there is more data
       * available.
       * @param max the maximum amount of data to retrieve
       */
      QPair<QByteArray, bool> GetData(int max);

      void AddMember(const GroupContainer &gc);
      void RemoveMember(const Id &id);

      /**
       * Used by the leader to queue Ready requests.
       */
      QHash<Id, RpcRequest> _id_to_request;

      /**
       * Used by a client to store messages to be sent for future rounds
       */
      QByteArray _send_queue;

      Group _group;
      Group _shared_group;
      QSet<Id> _bad_members;
      const Credentials _creds;
      const Id _session_id;
      QSharedPointer<Network> _network;
      CreateRound _create_round;

      QSharedPointer<Round> _current_round;
      RpcMethod _registered;
      RpcMethod _prepared;
      Dissent::Utils::TimerEvent _register_event;
      QDateTime _last_registration;
      Dissent::Utils::TimerEvent _prepare_event;
      QHash<Id, Id> _registered_peers;
      QHash<Id, Id> _prepared_peers;
      GetDataCallback _get_data_cb;
      int _round_idx;
      RpcRequest _prepare_request;
      bool _prepare_waiting;
      bool _prepare_waiting_for_con;
      int _trim_send_queue;

    private slots:
      /**
       * Called when a new connection is created
       */
      void HandleConnection(Connection *con);

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
