#include "SessionSharedState.hpp"

#include "Crypto/DiffieHellman.hpp"
#include "Crypto/DsaPrivateKey.hpp"
#include "Crypto/Hash.hpp"
#include "Utils/QRunTimeError.hpp"

#include "SerializeList.hpp"

namespace Dissent {
namespace Session {
  SessionSharedState::SessionSharedState(
      const QSharedPointer<ClientServer::Overlay> &overlay,
      const QSharedPointer<Crypto::AsymmetricKey> &my_key,
      const QSharedPointer<Crypto::KeyShare> &keys,
      Anonymity::CreateRound create_round) :
    m_round_announcer(new RoundAnnouncer),
    m_overlay(overlay),
    m_my_key(my_key),
    m_keys(keys),
    m_create_round(create_round)
  {
  }

  SessionSharedState::~SessionSharedState()
  {
  }

  void SessionSharedState::GenerateRoundData()
  {
    m_ephemeral_key = QSharedPointer<Crypto::AsymmetricKey>(new Crypto::DsaPrivateKey());
    Crypto::DiffieHellman dh_key;
    m_optional_public = dh_key.GetPublicComponent();
    m_optional_private = dh_key.GetPrivateComponent();
  }

  void SessionSharedState::SetServers(
      const QList<QSharedPointer<ServerAgree> > &servers)
  {
    m_server_list = servers;
    m_server_bytes = SerializeList<ServerAgree>(GetServers());
  }

  void SessionSharedState::CheckServerAgree(const ServerAgree &agree,
      const QByteArray &round_id)
  {
    if(agree.GetRoundId() != round_id) {
      throw Utils::QRunTimeError("RoundId mismatch. Expected: " +
          round_id.toBase64() + ", found: " +
          agree.GetRoundId().toBase64() + ", from " +
          agree.GetId().ToString());
    }

    QSharedPointer<Crypto::AsymmetricKey> key =
      GetKeyShare()->GetKey(agree.GetId().ToString());
    if(!key->Verify(agree.GetPayload(), agree.GetSignature())) {
      throw Utils::QRunTimeError("Invalid signature: " +
          agree.GetId().ToString());
    }

    if(!agree.GetKey()->IsValid()) {
      throw Utils::QRunTimeError("Invalid Ephemeral Key: " +
          agree.GetId().ToString());
    }
  }


  bool SessionSharedState::CheckServerStop(const ServerStop &stop)
  {
    if(stop.GetRoundId().isEmpty()) {
      throw Utils::QRunTimeError("Invalid RoundId");
    }

    QSharedPointer<Crypto::AsymmetricKey> key =
      GetKeyShare()->GetKey(stop.GetId().ToString());
    if(!key->Verify(stop.GetPayload(), stop.GetSignature())) {
      throw Utils::QRunTimeError("Invalid signature");
    }

    if(GetRoundId() != stop.GetRoundId()) {
      throw Utils::QRunTimeError("Stop RoundId mismatch. Expected: " +
          GetRoundId().toBase64() + ", found: " +
          stop.GetRoundId().toBase64() + ", from " +
          stop.GetId().ToString());
    }

    qDebug() << GetOverlay()->GetId() << "Stopping Round:" <<
      GetRoundId().toBase64() << "Reason:" << stop.GetReason() <<
      "Immediately: " << stop.GetImmediate();
    return stop.GetImmediate();
  }

  Messaging::State::ProcessResult SessionSharedState::DefaultHandleServerStop(
      const QSharedPointer<Messaging::ISender> &,
      const QSharedPointer<Messaging::Message> &msg)
  {
    Crypto::Hash hash;
    QByteArray hashvalue = hash.ComputeHash(msg->GetPacket());
    if(hashvalue == m_last) {
      return Messaging::State::NoChange;
    }
    m_last = hashvalue;

    QSharedPointer<ServerStop> stop = msg.dynamicCast<ServerStop>();
    CheckServerStop(*(msg.dynamicCast<ServerStop>()));

    if(GetOverlay()->GetServerIds().first() == GetOverlay()->GetId()) {
      qDebug() << "Received a ServerStop message from" << stop->GetId() << "... redistributing...";
      if(GetRoundId() == stop->GetRoundId()) {
        GetOverlay()->Broadcast("SessionData", msg->GetPacket());
      } else {
        GetOverlay()->BroadcastToServers("SessionData", msg->GetPacket());
      }
    } else {
      qDebug() << "Received a ServerStop message from" << stop->GetId();
    }
    return Messaging::State::Restart;
  }

  void SessionSharedState::NextRound()
  {
//    QSharedPointer<Buddies::BuddyPolicy> bp(new Buddies::NullBuddyPolicy(GetGroup().Count()));
//    QSharedPointer<Buddies::BuddyMonitor> bm(new Buddies::BuddyMonitor(bp));

    QVector<Identity::PublicIdentity> server_idents;
    foreach(const QSharedPointer<ServerAgree> &server, GetServers()) {
      Identity::PublicIdentity ident(server->GetId(), server->GetKey(),
          server->GetOptional().toByteArray());
      server_idents.append(ident);
    }

    QVector<Identity::PublicIdentity> client_idents;
    foreach(const QSharedPointer<ClientRegister> &client, GetClients()) {
      Identity::PublicIdentity ident(client->GetId(), client->GetKey(),
          client->GetOptional().toByteArray());
      client_idents.append(ident);
    }

    Identity::Roster clients(client_idents);
    Identity::Roster servers(server_idents);

    Crypto::DiffieHellman dh_key(GetOptionalPrivate().toByteArray(), false);
    Identity::PrivateIdentity my_ident(GetOverlay()->GetId(),
        GetEphemeralKey(), dh_key);
    m_round = m_create_round(clients, servers, my_ident,
          GetRoundId(), GetOverlay(), m_send_queue.GetCallback());

    GetRoundAnnouncer()->AnnounceHelper(m_round);
  }

  void SessionSharedState::AddData(const QByteArray &data)
  {
    m_send_queue.AddData(data);
  }

  QPair<QByteArray, bool> SessionSharedState::DataQueue::GetData(int max)
  {
    if(m_trim > 0) {
      m_queue = m_queue.mid(m_trim);
    }

    QByteArray data;
    int idx = 0;
    while(idx < m_queue.count()) {
      if(max < m_queue[idx].count()) {
        qDebug() << "Message in queue is larger than max data:" <<
          m_queue[idx].count() << "/" << max;
        idx++;
        continue;
      } else if(max < (data.count() + m_queue[idx].count())) {
        break;
      }

      data.append(m_queue[idx++]);
    }

    m_trim = idx;

    bool more = m_queue.count() != m_trim;
    return QPair<QByteArray, bool>(data, more);
  }

  void SessionSharedState::RoundFinished(const QSharedPointer<Anonymity::Round> &round)
  {
    if(!round->Successful()) {
      m_send_queue.UnGet();
    }
  }

  void RoundAnnouncer::AnnounceHelper(const QSharedPointer<Anonymity::Round> &round)
  {
    emit Announce(round);
  }
}
}
