#ifndef DISSENT_TESTS_TOLERANT_BULK_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_TOLERANT_BULK_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {

  typedef Dissent::Anonymity::Tolerant::TolerantBulkRound TolerantBulkRound;

  template<typename B, template <int> class S, int N> class TolerantBulkRoundBadKeyShuffler :
      public B, public Triggerable
  {
    public:
      explicit TolerantBulkRoundBadKeyShuffler(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        B(group, ident, round_id, network, get_data, TNCreateRound<S, N>)
      {
      }

      bool Triggered()
      {
        return TBadGuyCB<S<N> >(B::GetKeyShuffleRound().data());
      }
  };

  class TolerantBulkRoundBadUserMessageGenerator : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadUserMessageGenerator(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual QByteArray GenerateUserXorMessage()
      {
        QByteArray msg = TolerantBulkRound::GenerateUserXorMessage();
        if(!Triggered()) {
          QScopedPointer<Random> rand(CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator());

          // Flip a single byte of the message
          const int idx = rand->GetInt(0, msg.count());
          msg[idx] = ~msg[idx];

          SetTriggered();
        }

        return msg;
      }
  };

  class TolerantBulkRoundBadCleartextSigner : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadCleartextSigner(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual QByteArray SignMessage(const QByteArray &message)
      {
        QByteArray sig = TolerantBulkRound::SignMessage(message);
        if(!Triggered()) {
          sig = QByteArray(sig.count(), 0);
          SetTriggered();
        }

        return sig;
      }
  };

  class TolerantBulkRoundBadServerPad : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadServerPad(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual QByteArray GeneratePadWithServer(uint server_idx, uint length)
      {
        QByteArray server_pad(length, 0);
        GetRngsWithServers()[server_idx]->GenerateBlock(server_pad);

        if(!Triggered()) {
          FlipByte(server_pad); 
          SetTriggered();
        }

        return server_pad;
      }
  };

  class TolerantBulkRoundBadUserPad : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadUserPad(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual QByteArray GeneratePadWithUser(uint user_idx, uint length)
      {
        QByteArray user_pad(length, 0);
        GetRngsWithUsers()[user_idx]->GenerateBlock(user_pad);

        if(!Triggered()) {
          FlipByte(user_pad); 
          SetTriggered();
        }

        return user_pad;
      }
  };


  class TolerantBulkRoundBadUserAlibi : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadUserAlibi(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual QByteArray GenerateUserXorMessage()
      {
        QByteArray msg = TolerantBulkRound::GenerateUserXorMessage();
        if(!Triggered()) {
          QScopedPointer<Random> rand(CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator());

          // Flip a single byte of the message
          const int idx = rand->GetInt(0, msg.count());
          msg[idx] = ~msg[idx];

          SetTriggered();
        }

        return msg;
      }

      virtual void SendUserAlibis(const QMap<int, Accusation> &map) 
      {
        QByteArray alibi_bytes;
        for(QMap<int, Accusation>::const_iterator i=map.constBegin(); i!=map.constEnd(); ++i) {
          Accusation acc = i.value();
          QByteArray al = GetUserAlibiData().GetAlibiBytes(i.key(), acc);
          alibi_bytes.append(al);
        }

        // Flip first bit of alibi bytes
        alibi_bytes[0] = (alibi_bytes[0] ^ 1);

        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);
        stream << MessageType_UserAlibiData << GetRoundId() << GetPhase() << alibi_bytes;
        VerifiableBroadcast(packet);
      }
  };

  class TolerantBulkRoundBadServerAlibi : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadServerAlibi(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual QByteArray GenerateUserXorMessage()
      {
        QByteArray msg = TolerantBulkRound::GenerateUserXorMessage();
        if(!Triggered()) {
          QScopedPointer<Random> rand(CryptoFactory::GetInstance().GetLibrary()->GetRandomNumberGenerator());

          // Flip a single byte of the message
          const int idx = rand->GetInt(0, msg.count());
          msg[idx] = ~msg[idx];

          SetTriggered();
        }

        return msg;
      }

      virtual void SendServerAlibis(const QMap<int, Accusation> &map) 
      {
        QByteArray alibi_bytes;
        for(QMap<int, Accusation>::const_iterator i=map.constBegin(); i!=map.constEnd(); ++i) {
          Accusation acc = i.value();
          QByteArray al = GetServerAlibiData().GetAlibiBytes(i.key(), acc);
          alibi_bytes.append(al);
        }

        // Flip first bit of alibi bytes
        alibi_bytes[0] = (alibi_bytes[0] ^ 1);

        QByteArray packet;
        QDataStream stream(&packet, QIODevice::WriteOnly);
        stream << MessageType_ServerAlibiData << GetRoundId() << GetPhase() << alibi_bytes;
        VerifiableBroadcast(packet);
      }
  };

  class TolerantBulkRoundBadUserCommit : public TolerantBulkRound, public Triggerable
  {
    public:
      
      explicit TolerantBulkRoundBadUserCommit(const Group &group,
          const PrivateIdentity &ident, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        TolerantBulkRound(group, ident, round_id, network, get_data)
      {}

      virtual void FinishCommitPhase()
      {
        ChangeState(State_DataSharing);

        QByteArray user_packet = GetNextUserPacket();
        if(!Triggered()) {
          SetTriggered();
          FlipByte(user_packet);
        }
        VerifiableBroadcast(user_packet);
        if(IsServer()) {
          VerifiableBroadcast(GetNextServerPacket());
        }
      }
  };

}
}

#endif
