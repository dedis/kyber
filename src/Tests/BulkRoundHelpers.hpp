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
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        B(group, creds, round_id, network, get_data, TNCreateRound<S, N>)
      {
      }

      bool Triggered()
      {
        return TBadGuyCB<S<N> >(B::GetShuffleRound().data());
      }
  };

  template <typename B, template <int> class S, int N> Round *TBNCreateRound(
      const Group &group, const Credentials &creds,
      const Dissent::Connections::Id &round_id,
      QSharedPointer<Dissent::Connections::Network> network,
      Dissent::Messaging::GetDataCallback &get_data)
  {
    return new BulkRoundBadShuffler<B, S, N>(group, creds, round_id,
        network, get_data);
  };

  class BulkRoundIncorrectMessageLength : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundIncorrectMessageLength(const Group &group,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group, creds, round_id, network, get_data),
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
        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
        msg.resize(rng->GetInt(0, msg.size()));
        rng->GenerateBlock(msg);
        return msg;
      }

    private:
      int _bad;
  };

  class BulkRoundBadXorMessage : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundBadXorMessage(const Group &group,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group, creds, round_id, network, get_data),
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
        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        QScopedPointer<Random> rng(lib->GetRandomNumberGenerator());
        rng->GenerateBlock(msg);
        return msg;
      }

    private:
      int _bad;
  };

  class BulkRoundBadDescriptor : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundBadDescriptor(const Group &group,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group, creds, round_id, network, get_data)
      {
      }

    private:
      virtual QPair<QByteArray, bool> GetBulkData(int)
      {
        SetTriggered();

        int length = 2048;
        QByteArray data(length, 0);

        Library *lib = CryptoFactory::GetInstance().GetLibrary();
        QScopedPointer<Hash> hashalgo(lib->GetHashAlgorithm());

        QByteArray xor_message(length, 0);
        QVector<QByteArray> hashes;

        int my_idx = GetGroup().GetIndex(GetLocalId());

        foreach(const GroupContainer &gc, GetGroup().GetRoster()) {
          QByteArray seed = GetAnonDh()->GetSharedSecret(gc.third);

          if(hashes.size() == my_idx) {
            hashes.append(QByteArray());
            continue;
          }

          QByteArray msg(length, 0);
          QScopedPointer<Random> rng(lib->GetRandomNumberGenerator(seed));
          rng->GenerateBlock(msg);
          hashes.append(hashalgo->ComputeHash(msg));
          Xor(xor_message, xor_message, msg);
        }

        QByteArray my_xor_message = QByteArray(length, 0);
        Xor(my_xor_message, xor_message, data);
        SetMyXorMessage(my_xor_message);
        hashes[my_idx] = hashalgo->ComputeHash(my_xor_message);

        int bad = Random::GetInstance().GetInt(0, GetGroup().Count());
        while(bad == my_idx) {
          bad = Random::GetInstance().GetInt(0, GetGroup().Count());
        }

        qDebug() << my_idx << "setting bad hash at" << bad;
        hashes[bad] = hashalgo->ComputeHash(xor_message);

        Descriptor descriptor(length, GetAnonDh()->GetPublicComponent(), hashes);
        SetMyDescriptor(descriptor);

        QByteArray my_desc;
        QDataStream desstream(&my_desc, QIODevice::WriteOnly);
        desstream << descriptor;
        return QPair<QByteArray, bool>(my_desc, false);
      }
  };

  /// @todo not implemented
  class BulkRoundFalseAccusation : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundFalseAccusation(const Group &group,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group, creds, round_id, network, get_data)
      {
      }
  };
}
}

#endif
