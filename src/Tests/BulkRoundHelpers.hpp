#ifndef DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD
#define DISSENT_TESTS_BULK_ROUND_HELPERS_H_GUARD

#include "DissentTest.hpp"

namespace Dissent {
namespace Tests {
  template<typename T> class BulkRoundBadShuffler : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundBadShuffler(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group_gen, creds, round_id, network, get_data, TCreateRound<T>)
      {
      }

      bool Triggered()
      {
        return TBadGuyCB<T>(GetShuffleRound().data());
      }
  };

  class BulkRoundIncorrectMessageLength : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundIncorrectMessageLength(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group_gen, creds, round_id, network, get_data),
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
      explicit BulkRoundBadXorMessage(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group_gen, creds, round_id, network, get_data),
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
      explicit BulkRoundBadDescriptor(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group_gen, creds, round_id, network, get_data)
      {
      }
  };

  /// @todo not implemented
  class BulkRoundFalseAccusation : public BulkRound, public Triggerable {
    public:
      explicit BulkRoundFalseAccusation(QSharedPointer<GroupGenerator> group_gen,
          const Credentials &creds, const Id &round_id,
          QSharedPointer<Network> network, GetDataCallback &get_data) :
        BulkRound(group_gen, creds, round_id, network, get_data)
      {
      }
  };
}
}

#endif
