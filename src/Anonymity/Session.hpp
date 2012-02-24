#ifndef DISSENT_ANONYMITY_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SESSION_H_GUARD

#include <QHash>
#include <QObject>
#include <QQueue>
#include <QSet>

#include "Connections/Id.hpp"
#include "Identity/Credentials.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/Request.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/TimerEvent.hpp"

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
  class Response;
  class ResponseHandler;
}

namespace Anonymity {
  /**
   * Maintains a (variable) set of peers (group) which is actively
   * participating in anonymous exchanges (rounds).
   */
  class Session : public Messaging::FilterObject,
    public Utils::StartStop
  {
    Q_OBJECT

    public:
      typedef Connections::Connection Connection;
      typedef Connections::Id Id;
      typedef Connections::Network Network;
      typedef Crypto::AsymmetricKey AsymmetricKey;
      typedef Identity::Credentials Credentials;
      typedef Identity::Group Group;
      typedef Identity::GroupContainer GroupContainer;
      typedef Identity::GroupHolder GroupHolder;
      typedef Messaging::Request Request;
      typedef Messaging::Response Response;
      typedef Messaging::ResponseHandler ResponseHandler;
      typedef Messaging::GetDataMethod<Session> GetDataCallback;

      /**
       * Constructor
       * @param group_holder contains the anonymity group
       * @param creds the local nodes credentials
       * @param session_id Id for the session
       * @param network handles message sending
       * @param create_round a callback for creating a secure round
       */
      explicit Session(const QSharedPointer<GroupHolder> &group_holder,
          const Credentials &creds, const Id &session_id,
          QSharedPointer<Network> network, CreateRound create_round);

      /**
       * Deconstructor
       */
      virtual ~Session();

      /**
       * From the SessionManager, pass in a ReceivedRegister
       * @param request The request from a group member
       */
      void ReceivedRegister(const Request &request);

      /**
       * From the SessionManager, pass in a ReceiveReady
       * @param request The request from the leader
       */
      void ReceivedPrepare(const Request &request);

      /**
       * From the SessionManager, pass in a Begin message from the Session
       * leader to call start on the round
       * @param notification The notification from the leader
       */
      void ReceivedBegin(const Request &notification);

      /**
       * From the SessionManager, pass in incoming data
       * @param notification The message containing the data
       */
      void IncomingData(const Request &notification);

      /**
       * From a client software, send a message anonymously
       */
      virtual void Send(const QByteArray &data);

      /**
       * Returns true if the peer is the leader for this session
       */
      inline bool IsLeader() const
      {
        return _creds.GetLocalId() == GetGroup().GetLeader();
      }

      /**
       * Returns the Session Id
       */
      inline const Id &GetId() const { return _session_id; }

      /**
       * Returns the current round
       */
      inline QSharedPointer<Round> GetCurrentRound()
      {
        return _current_round;
      }

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
      inline Group GetGroup() const { return _group_holder->GetGroup(); }

      /**
       * Get the set of bad group members
       */
      inline const QSet<Id> GetBadMembers() const { return _bad_members; }

      static const int MinimumRoundSize = 3;

      static const int PeerJoinDelay = 10000;

      const GroupHolder &GetGroupHolder();

    signals:
      /**
       * Signals that a round is beginning.
       * @param round _current_round
       */
      void RoundStarting(const QSharedPointer<Round> &round);

      /**
       * Signals that a round has completed.  The round will be deleted after
       * the signal has returned.
       * @param round _current_round
       */
      void RoundFinished(const QSharedPointer<Round> &round);

      /**
       * Signfies that the session has been closed / stopped
       */
      void Stopping();

    public slots:
      /**
       * Calls start
       */
      void CallStart()
      {
        Start();
      }

      /**
       * Calls stop
       */
      void CallStop()
      {
        Stop();
      }

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
      QHash<Id, Request> _id_to_request;

      /**
       * Used by a client to store messages to be sent for future rounds
       */
      QByteArray _send_queue;

      Group _shared_group;
      QSet<Id> _bad_members;
      QSharedPointer<GroupHolder> _group_holder;
      const Credentials _creds;
      const Id _session_id;
      QSharedPointer<Network> _network;
      CreateRound _create_round;

      QSharedPointer<Round> _current_round;
      Utils::TimerEvent _register_event;
      QDateTime _last_registration;
      Utils::TimerEvent _prepare_event;
      QHash<Id, Id> _registered_peers;
      QHash<Id, Id> _prepared_peers;
      QSharedPointer<ResponseHandler> _prepared;
      QSharedPointer<ResponseHandler> _registered;
      GetDataCallback _get_data_cb;
      int _round_idx;
      Request _prepare_request;
      bool _prepare_waiting;
      bool _prepare_waiting_for_con;
      int _trim_send_queue;

    private slots:
      /**
       * Called when a new connection is created
       * @param con the new connection
       */
      void HandleConnection(const QSharedPointer<Connection> &con);

      /**
       * Called when the current round has finished
       */
      virtual void HandleRoundFinished();

      /**
       * Called when a remote peer has disconnected from the session
       */
      virtual void HandleDisconnect();

      /**
       * Contains acknowledgement from the registration request
       * @param response the response may be positive or negative
       */
      void Registered(const Response &response);

      /**
       */
      void Prepared(const Response &response);
  };
}
}

#endif
