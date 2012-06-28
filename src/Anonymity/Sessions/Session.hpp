#ifndef DISSENT_ANONYMITY_SESSION_H_GUARD
#define DISSENT_ANONYMITY_SESSION_H_GUARD

#include <QList>
#include <QObject>

#include "Anonymity/Round.hpp"
#include "Connections/Id.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/Group.hpp"
#include "Identity/GroupHolder.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/Request.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/TimerEvent.hpp"

namespace Dissent {
namespace Connections {
  class Connection;
  class Network;
}

namespace Messaging {
  class Response;
  class ResponseHandler;
}

namespace Anonymity {
namespace Sessions {
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
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Identity::Group Group;
      typedef Identity::GroupHolder GroupHolder;
      typedef Messaging::Request Request;
      typedef Messaging::Response Response;
      typedef Messaging::ResponseHandler ResponseHandler;
      typedef Messaging::GetDataMethod<Session> GetDataCallback;

      /**
       * Constructor
       * @param group_holder contains the anonymity group
       * @param ident the local nodes credentials
       * @param session_id Id for the session
       * @param network handles message sending
       * @param create_round a callback for creating a secure round
       */
      explicit Session(const QSharedPointer<GroupHolder> &group_holder,
          const PrivateIdentity &ident, const Id &session_id,
          QSharedPointer<Network> network, CreateRound create_round);

      /**
       * Deconstructor
       */
      virtual ~Session();

      /**
       * From a client software, send a message anonymously
       */
      virtual void Send(const QByteArray &data);

      /**
       * Returns the Session Id
       */
      inline const Id &GetSessionId() const { return _session_id; }

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
        return "Session: " + GetSessionId().ToString() + "|" +
          (_current_round.isNull() ? "No current round" : 
          _current_round->ToString());
      }

      /**
       * Returns the group being used in this session
       */
      inline Group GetGroup() const { return _group_holder->GetGroup(); }

      static const int MinimumRoundSize = 3;

      const QSharedPointer<GroupHolder> &GetGroupHolder() { return _group_holder; }

      /**
       * Returns true if the group is formed well enough to start the round
       */
      virtual bool CheckGroup(const Group &group);

      /**
       * Older version
       */
      inline bool CheckGroup() { return CheckGroup(GetGroup()); }

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

      /**
       * From the SessionManager, pass in a ReceiveReady
       * @param request The request from the leader
       */
      void HandlePrepare(const Request &notification);

      /**
       * From the SessionManager, pass in a Begin message from the Session
       * leader to call start on the round
       * @param notification The notification from the leader
       */
      void HandleBegin(const Request &notification);

      /**
       * From the SessionManager, pass in incoming data
       * @param notification The message containing the data
       */
      void IncomingData(const Request &notification);


    protected:
      /**
       * Called when the session is started
       */
      virtual void OnStart();

      /**
       * Called when the session is stopped
       */
      virtual void OnStop();

      /**
       * Returns the network for this round
       */
      inline QSharedPointer<Network> GetNetwork() { return _network; }

      /**
       * Called when a connection with a peer has been established
       */
      virtual void HandleConnection(const QSharedPointer<Connection> &con);

      /**
       * Called when a member has disconnected
       */
      virtual void HandleDisconnect(const Id &remote_id);

      /**
       * Called when a round has finished
       */
      virtual void HandleRoundFinished();

    private:
      /**
       * Called upon starting to register this peer with the leader
       * @param unused unused
       */
      void Register(const int &unused = 0);

      /**
       * Called to start the next Round
       */
      void NextRound(const Id &round_id);

      /**
       * Returns true if this instance should register
       */
      virtual bool ShouldRegister();

      /**
       * Retrieves data from the data waiting queue, returns the byte array
       * containing data and a bool which is true if there is more data
       * available.
       * @param max the maximum amount of data to retrieve
       */
      QPair<QByteArray, bool> GetData(int max);

      /**
       * Used by a client to store messages to be sent for future rounds
       */
      QList<QByteArray> _send_queue;

      Utils::TimerEvent _register_event;
      QSharedPointer<GroupHolder> _group_holder;
      const Group _base_group;
      const PrivateIdentity _ident;
      const Id _session_id;
      QSharedPointer<Network> _network;
      CreateRound _create_round;

      QSharedPointer<Round> _current_round;
      QSharedPointer<ResponseHandler> _registered;
      GetDataCallback _get_data_cb;
      Request _prepare_notification;
      bool _prepare_waiting;
      int _trim_send_queue;
      bool _registering;

    private slots:
      /**
       * Contains acknowledgement from the registration request
       * @param response the response may be positive or negative
       */
      void Registered(const Response &response);

      /**
       * Called when a new connection is created
       * @param con the new connection
       */
      void HandleConnectionSlot(const QSharedPointer<Connection> &con);

      /**
       * Called when the current round has finished
       */
      virtual void HandleRoundFinishedSlot();

      /**
       * Called when a remote peer has disconnected from the session
       */
      virtual void HandleDisconnectSlot();
  };
}
}
}

#endif
