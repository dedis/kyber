#ifndef DISSENT_ANONYMITY_ROUND_H_GUARD
#define DISSENT_ANONYMITY_ROUND_H_GUARD

#include <QDateTime>
#include <QObject>
#include <QSharedPointer>

#include "ClientServer/Overlay.hpp"
#include "Connections/Id.hpp"
#include "Identity/Roster.hpp"
#include "Identity/PrivateIdentity.hpp"
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
      /**
       * Constructor
       * @param clients the list of clients in the round
       * @param servers the list of servers in the round
       * @param ident this participants private information
       * @param nonce Unique round id (nonce)
       * @param overlay handles message sending
       * @param get_data requests data to share during this session
       */
      explicit Round(const Identity::Roster &clients,
          const Identity::Roster &servers,
          const Identity::PrivateIdentity &ident,
          const QByteArray &nonce,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          Messaging::GetDataCallback &get_data);

      /**
       * Destructor
       */
      virtual ~Round() {}

      /**
       * Handle a data message from a remote peer
       * @param from The remote sender
       * @param msg The message
       */
      virtual void ProcessPacket(const Connections::Id &from, const QByteArray &msg) = 0;

      /**
       * Returns whether or not there were any problems in the round
       */
      inline bool Successful() const { return m_successful; }

      /**
       * Returns the local id
       */
      inline const Connections::Id GetLocalId() const { return m_ident.GetId(); }

      /**
       * Returns the round nonce
       */
      inline QByteArray GetNonce() const { return m_nonce; }

      /**
       * Returns the client roster used in the round
       */
      inline const Identity::Roster &GetClients() const { return m_clients; }

      /**
       * Returns the server roster used in the round
       */
      inline const Identity::Roster &GetServers() const { return m_servers; }

      /**
       * Returns the list of bad nodes discovered in the round
       */
      inline virtual const QVector<int> &GetBadMembers() const
      {
        return m_empty_list;
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
      virtual void HandleDisconnect(const Connections::Id &id);

      inline virtual QString ToString() const { return "Round"; }

      /**
       * Notifies the round of a new peer wanting to join.  Default behavior is
       * to do nothing and wait for the next round.
       */
      virtual void PeerJoined() {}

      /**
       * Was the round interrupted?  Should the leader interrupt others.
       */
      bool Interrupted() { return m_interrupted; }

      /**
       * Round interrupted, leader should interrupt others.
       */
      void SetInterrupted() { m_interrupted = true; }

      inline QSharedPointer<Round> GetSharedPointer()
      {
        return m_shared.toStrongRef();
      }

      void SetSharedPointer(const QSharedPointer<Round> &shared)
      {
        m_shared = shared.toWeakRef();
      }

      /**
       * Returns the time the Round was created
       */
      QDateTime GetCreateTime() const { return m_create_time; }

      /**
       * Returns the time Start was called
       */
      QDateTime GetStartTime() const { return m_start_time; }

      /**
       * Sets the header bytes
       */
      void SetHeaderBytes(const QByteArray &header) { m_header = header; }

      /**
       * Return the header bytes
       */
      QByteArray GetHeaderBytes() const { return m_header; }

    signals:
      /**
       * Emitted when the Round is closed for good or bad.
       */
      void Finished();

    protected:
      /**
       * Called on Round Start
       */
      virtual void OnStart();

      /**
       * Called on Round Stop
       */
      virtual void OnStop();

      /**
       * Verifies that the provided data has a signature block and is properly
       * signed, returning the data block via msg
       * @param from the signing peers id
       * @param data the data + signature blocks
       * @param msg the data block
       */
      bool Verify(const Connections::Id &from, const QByteArray &data, QByteArray &msg);

      /**
       * Signs and encrypts a message before sending it to all participants
       * @param data the message to send
       */
      void VerifiableBroadcast(const QByteArray &data);

      /**
       * Signs and encrypts a message before sending it to all downstream clients
       * @param data the message to send
       */
      void VerifiableBroadcastToClients(const QByteArray &data);

      /**
       * Signs and encrypts a message before sending it to all servers
       * @param data the message to send
       */
      void VerifiableBroadcastToServers(const QByteArray &data);

      /**
       * Signs and encrypts a message before sending it to a sepecific peer
       * @param to the peer to send it to
       * @param data the message to send
       */
      void VerifiableSend(const Connections::Id &to,
          const QByteArray &data);

      /**
       * Returns the data to be sent during this round
       */
      inline const QPair<QByteArray, bool> GetData(int max)
      {
        return m_get_data_cb(max);
      }

      /**
       * Returns the nodes signing key
       */
      inline QSharedPointer<Crypto::AsymmetricKey> GetKey() const
      {
        return m_ident.GetKey();
      }

      /**
       * Returns the local credentials
       */
      inline const Identity::PrivateIdentity &GetPrivateIdentity() const
      {
        return m_ident;
      }

      /**
       * Returns the DiffieHellman key
       */
      inline const Crypto::DiffieHellman GetDhKey() const
      {
        return m_ident.GetDhKey();
      }

      void SetSuccessful(bool successful) { m_successful = successful; }

      /**
       * Returns the underlyign network
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() { return m_overlay; }

      /**
       * Returns the underlyign network
       */
      QSharedPointer<ClientServer::Overlay> GetOverlay() const { return m_overlay; }

      static constexpr float PERCENT_ACTIVE = -1.0;

      static const int DEFAULT_GENERATE_DATA_SIZE = 256;

      /**
       * Generates a random data array
       */
      QByteArray GenerateData(int size = DEFAULT_GENERATE_DATA_SIZE);

      /**
       * Wrapper around Source::PushData to assist with buddies
       * @param uid anonymous id
       * @param data data to push
       */
      void PushData(int uid, const QByteArray &data);

      /**
       * Make Source::PushData available
       */
      inline void PushData(const QSharedPointer<Messaging::ISender> &sender,
          const QByteArray &data)
      {
        Messaging::SourceObject::PushData(sender, data);
      }

    private:
      QDateTime m_create_time;
      QDateTime m_start_time;
      const Identity::Roster m_clients;
      const Identity::Roster m_servers;
      const Identity::PrivateIdentity m_ident;
      const QByteArray m_nonce;
      QSharedPointer<ClientServer::Overlay> m_overlay;
      Messaging::GetDataCallback &m_get_data_cb;
      bool m_successful;
      QVector<int> m_empty_list;
      bool m_interrupted;
      QWeakPointer<Round> m_shared;
      QByteArray m_header;
  };

  inline QDebug operator<<(QDebug dbg, const QSharedPointer<Round> &round)
  {
    dbg.nospace() << round->ToString();
    return dbg.space();
  }

  inline QDebug operator<<(QDebug dbg, const Round *round)
  {
    dbg.nospace() << round->ToString();
    return dbg.space();
  }

  typedef QSharedPointer<Round> (*CreateRound)(
      const Identity::Roster &,
      const Identity::Roster &,
      const Identity::PrivateIdentity &,
      const QByteArray &,
      const QSharedPointer<ClientServer::Overlay> &,
      Messaging::GetDataCallback &get_data_cb);

  template <typename T> QSharedPointer<Round> TCreateRound(
      const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<T> round(new T(clients, servers, ident, nonce, overlay, get_data));
    round->SetSharedPointer(round);
    return round;
  }
}
}

#endif
