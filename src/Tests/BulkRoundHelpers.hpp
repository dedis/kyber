#ifndef DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"
#include "RoundTest.hpp"

namespace Dissent {
namespace Tests {
  template<typename B, template <int> class S, int N> class BulkRoundBadShuffler :
      public B, public Triggerable
  {
    public:
      explicit BulkRoundBadShuffler(const Group &group,
          const PrivateIdentity &ident,
          const Id &round_id,
          const QSharedPointer<Network> &network,
          GetDataCallback &get_data,
          const QSharedPointer<BuddyMonitor> &bm) :
        B(group, ident, round_id, network, get_data, bm,
            TNCreateRound<S, N>)
      {
      }

      bool Triggered()
      {
        return TBadGuyCB<S<N> >(B::GetShuffleRound().data());
      }
  };

  template <typename B, template <int> class S, int N> Round *TBNCreateRound(
      const Group &group,
      const PrivateIdentity &ident,
      const Dissent::Connections::Id &round_id,
      const QSharedPointer<Dissent::Connections::Network> &network,
      Dissent::Messaging::GetDataCallback &get_data,
      const QSharedPointer<BuddyMonitor> &bm)
  {
    return new BulkRoundBadShuffler<B, S, N>(group, ident, round_id,
        network, get_data, bm);
  };

  class BulkRoundIncorrectMessageLength : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundIncorrectMessageLength(const Group &group,
          const PrivateIdentity &ident,
          const Id &round_id,
          const QSharedPointer<Network> network,
          GetDataCallback &get_data,
          const QSharedPointer<BuddyMonitor> &bm) :
        BulkRound(group, ident, round_id, network, get_data, bm),
        _bad(-1)
      {
      }

      virtual QByteArray GenerateXorMessage(int idx)
      { 
        if(_bad == -1) {
          _bad = Random::GetInstance().GetInt(0, GetShuffleSink().Count());
        }

        QByteArray msg = BulkRound::GenerateXorMessage(idx);
        if(GetDescriptors().size() != _bad + 1) {
          return msg;
        }
        
        SetTriggered();
        CryptoRandom rng;
        msg.resize(rng.GetInt(0, msg.size()));
        rng.GenerateBlock(msg);
        return msg;
      }

    private:
      int _bad;
  };

  class BulkRoundBadXorMessage : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundBadXorMessage(const Group &group,
          const PrivateIdentity &ident,
          const Id &round_id,
          const QSharedPointer<Network> &network,
          GetDataCallback &get_data,
          const QSharedPointer<BuddyMonitor> &bm) :
        BulkRound(group, ident, round_id, network, get_data, bm),
        _bad(-1)
      {
      }

      virtual QByteArray GenerateXorMessage(int idx)
      { 
        if(_bad == -1) {
          _bad = Random::GetInstance().GetInt(0, GetShuffleSink().Count());
        }

        QByteArray msg = BulkRound::GenerateXorMessage(idx);
        if(GetDescriptors().size() != _bad + 1) {
          return msg;
        }
        
        SetTriggered();
        CryptoRandom().GenerateBlock(msg);
        return msg;
      }

    private:
      int _bad;
  };

  class BulkRoundBadDescriptor : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundBadDescriptor(const Group &group,
          const PrivateIdentity &ident,
          const Id &round_id,
          const QSharedPointer<Network> &network,
          GetDataCallback &get_data,
          const QSharedPointer<BuddyMonitor> &bm) :
        BulkRound(group, ident, round_id, network, get_data, bm)
      {
      }

    protected:
      virtual QPair<QByteArray, bool> GetBulkData(int)
      {
        QByteArray data(1024, 0);
        CreateDescriptor(data);

        SetTriggered();
        int my_idx = GetGroup().GetIndex(GetLocalId());
        int bad = Random::GetInstance().GetInt(0, GetGroup().Count());
        while(bad == my_idx) {
          bad = Random::GetInstance().GetInt(0, GetGroup().Count());
        }

        qDebug() << my_idx << "setting bad hash at" << bad;
        const Descriptor &cdes = GetMyDescriptor();
        QVector<QByteArray> hashes = cdes.XorMessageHashes();

        hashes[bad] = Hash().ComputeHash(data);

        Descriptor descriptor(cdes.Length(), cdes.PublicDh(), hashes,
            cdes.CleartextHash());
        SetMyDescriptor(descriptor);

        QByteArray my_desc;
        QDataStream desstream(&my_desc, QIODevice::WriteOnly);
        desstream << GetMyDescriptor();
        return QPair<QByteArray, bool>(my_desc, false);
      }
  };

  /// @todo not implemented
  class BulkRoundFalseAccusation : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundFalseAccusation(const Group &group,
          const PrivateIdentity &ident,
          const Id &round_id,
          const QSharedPointer<Network> &network,
          GetDataCallback &get_data,
          const QSharedPointer<BuddyMonitor> &bm) :
        BulkRound(group, ident, round_id, network, get_data, bm)
      {
      }
  };
}
}

#endif
