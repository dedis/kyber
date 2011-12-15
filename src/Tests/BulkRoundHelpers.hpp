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

      virtual QByteArray GenerateXorMessage(const QByteArray &descriptor)
      { 
        if(_bad == -1) {
          _bad = Random::GetInstance().GetInt(0, GetShuffleSink().Count());
        }

        QByteArray msg = BulkRound::GenerateXorMessage(descriptor);
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

      virtual QByteArray GenerateXorMessage(const QByteArray &descriptor)
      { 
        if(_bad == -1) {
          _bad = Random::GetInstance().GetInt(0, GetShuffleSink().Count());
        }

        QByteArray msg = BulkRound::GenerateXorMessage(descriptor);
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

  /// @todo not implemented
  class BulkRoundBadDescriptor : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundBadDescriptor(const Group &group,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group, creds, round_id, network, get_data)
      {
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
