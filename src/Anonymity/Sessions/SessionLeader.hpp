#ifndef DISSENT_ANONYMITY_SESSION_LEADER_H_GUARD
#define DISSENT_ANONYMITY_SESSION_LEADER_H_GUARD

#include <QList>
#include <QHash>
#include <QObject>
#include <QQueue>
#include <QSet>

#include "Anonymity/Round.hpp"
#include "Connections/Id.hpp"
#include "Identity/Authentication/IAuthenticator.hpp"
#include "Identity/PublicIdentity.hpp"
#include "Identity/PrivateIdentity.hpp"
#include "Identity/Group.hpp"
#include "Messaging/FilterObject.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Messaging/Request.hpp"
#include "Utils/StartStop.hpp"
#include "Utils/TimerEvent.hpp"

#include "Session.hpp"

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
}

namespace Anonymity {
namespace Sessions {
  /**
   * Maintains a (variable) set of peers (group) which is actively
   * participating in anonymous exchanges (rounds).
   * @todo this class could be further decoupled from session...
   * Actual sessions could notify the leader of disconnects (which is done) and
   * round conclusions (which is hacked by the leader actually participating).
   * @todo remove disconnect notification from rounds, only the leader should
   * make decisions, members can just wait until the leader thinks its real
   * members should reconnect anyway...
   */
  class SessionLeader : public QObject, public Utils::StartStop
  {
    Q_OBJECT

    public:
      typedef Connections::Connection Connection;
      typedef Connections::Id Id;
      typedef Connections::Network Network;
      typedef Crypto::AsymmetricKey AsymmetricKey;
      typedef Identity::PrivateIdentity PrivateIdentity;
      typedef Identity::PublicIdentity PublicIdentity;
      typedef Identity::Group Group;
      typedef Messaging::ISender ISender;
      typedef Messaging::Request Request;
      typedef Messaging::Response Response;
      typedef Messaging::GetDataMethod<SessionLeader> GetDataCallback;

      /**
       * Constructor
       * @param group_holder contains the anonymity group
       * @param ident the local nodes credentials
       * @param session_id Id for the session
       * @param network handles message sending
       * @param create_round a callback for creating a secure round
       */
      explicit SessionLeader(const Group &group,
          const PrivateIdentity &ident, QSharedPointer<Network> network,
          const QSharedPointer<Session> &session,
          const QSharedPointer<Identity::Authentication::IAuthenticator> &auth);

      /**
       * Deconstructor
       */
      virtual ~SessionLeader();

      /**
       * Returns the SessionLeader / Round information
       */
      inline virtual QString ToString() const
      {
        return "Leader: " + _session->GetSessionId().ToString() + "|" +
          (_session->GetCurrentRound() ? _session->GetCurrentRound()->ToString() :
           "No current round");
      }

      /**
       * Returns the group being used in this session
       */
      inline const Group GetGroup() const
      {
        if(_registered.size() > 0) {
          QVector<PublicIdentity> roster = _group.GetRoster() +
            _registered.values().toVector();
          SessionLeader *cthis = const_cast<SessionLeader *>(this);
          cthis->_group = Group(roster, _group.GetLeader(),
              _group.GetSubgroupPolicy(), _group.GetSubgroup().GetRoster());
          cthis->_registered.clear();
        }
        return _group;
      }

      /**
       * Get the set of bad group members
       */
//      inline const QSet<Id> GetBadMembers() const { return _bad_members; }

      /**
       * Time between a null or stopped round when peers are actively joining
       */
#if DISSENT_TEST
      static const int InitialPeerJoinDelay = 1000;
#else
      static const int InitialPeerJoinDelay = 30000;
#endif

      /**
       * Time between rounds if the round is active and peers have requested to join
       */
#if DISSENT_TEST
      static const int RoundRunningPeerJoinDelay = 1000;
#else
      static const int RoundRunningPeerJoinDelay = 600000;
#endif

      /**
       * Period between checking log off times
       */
      static const int LogOffCheckPeriod = 60000;

      /**
       * How long a period a peer needs to wait before they can register for a
       * session again
       */
      static const int LogOffPeriod = 600000;

      static bool EnableLogOffMonitor;

      inline const Id &GetSessionId() const { return _session->GetSessionId(); }

    signals:
      /**
       * Signifies that the SessionLeader has been closed / stopped
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
       * A remote peer is notifying a leader that a link was disconnected
       * @param notification contains the id of the disconnected member
       */
      void LinkDisconnect(const Request &notification);

      /**
       * A member wants to join, begins the initiation for joining.
       * @param request a request to be included
       */
      void HandleChallengeRequest(const Request &request);

      /**
       * This combines with register to actually enable a member to join a round
       * @param response a request to join
       */
      void HandleChallengeResponse(const Request &request);

      /**
       * Response to a prepare
       */
      void HandlePrepared(const Request &notification);
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
       * Called when a member has disconnected
       */
      virtual void HandleDisconnect(const Id &remote_id);

    private:
      inline QSharedPointer<Round> GetCurrentRound()
      {
        return _session->GetCurrentRound();
      }

      /**
       * Sets up calls to CheckRegistrationCallback
       */
      void CheckRegistration();

      /**
       * Called upon registration / round finished to start a new round
       * @param unused
       */
      void CheckRegistrationCallback(const int &);

      /**
       * Log off times to see if we can allow recent disconnects to reconnect
       * @param unused
       */
      void CheckLogOffTimes(const int &);

      /**
       * Checks to see if the leader has received all the Ready messsages and
       * broadcasts responses if it has.
       */
      bool SendPrepare();

      /**
       * If enough prepares have been issued, start a round
       */
      void CheckPrepares();

      virtual void AddMember(const PublicIdentity &gc);
      void RemoveMember(const Id &id);
      bool AllowRegistration(const QSharedPointer<ISender> &from,
          const PublicIdentity &ident);

      Group _group;
      const PrivateIdentity _ident;
      QSharedPointer<Network> _network;
      QSharedPointer<Session> _session;

      /**
       * Used by the leader to queue Ready requests.
       */
      QHash<Id, Request> _id_to_request;

      QDateTime _last_registration;
      Utils::TimerEvent _prepare_event;
      Utils::TimerEvent _check_log_off_event;
      QHash<Id, Id> _registered_peers;
      QList<Id> _prepared_peers;
      QHash<Id, Id> _unprepared_peers;
      int _round_idx;
      QHash <Id, qint64> _log_off_time;
      QSharedPointer<Identity::Authentication::IAuthenticator> _auth;
      QHash <Id, PublicIdentity> _registered;

    private slots:
      /**
       * Called when a new connection is created
       * @param con the new connection
       */
      void HandleConnectionSlot(const QSharedPointer<Connection> &con);

      /**
       * Called when a remote peer has disconnected from the session
       */
      virtual void HandleDisconnectSlot();

      /**
       * Called when a round has finished
       */
      virtual void HandleRoundFinished();
  };
}
}
}

#endif
