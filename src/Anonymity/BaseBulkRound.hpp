#ifndef DISSENT_ANONYMITY_BASE_BULK_ROUND_H_GUARD
#define DISSENT_ANONYMITY_BASE_BULK_ROUND_H_GUARD

#include <QMetaEnum>
#include <QSharedPointer>

#include "Messaging/BufferSink.hpp"
#include "Messaging/GetDataCallback.hpp"
#include "Utils/TimerEvent.hpp"
#include "Utils/Triple.hpp"
#include "Utils/Random.hpp"

#include "Log.hpp"
#include "Round.hpp"

namespace Dissent {
namespace Crypto {
  class DiffieHellman;
}

namespace Utils {
  class Random;
}

namespace Anonymity {
  class ShuffleRound;

  /**
   * Provides the basis for DC-net exchanges setup the Dissent way: shuffle
   * for setting up anonymous slots followed by one or more DC-net exchange(s).
   */
  class BaseBulkRound : public Round {
    Q_OBJECT

    public:
      typedef Messaging::BufferSink BufferSink;
      typedef Messaging::GetDataMethod<BaseBulkRound> BulkGetDataCallback;

      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit BaseBulkRound(const Group &group, const PrivateIdentity &ident,
          const Id &round_id, QSharedPointer<Network> network,
          GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<ShuffleRound>);

      /**
       * Destructor
       */
      virtual ~BaseBulkRound() {}

      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingData(const Request &notification);

      /**
       * Returns the ShuffleRound used to exchange descriptors
       */
      QSharedPointer<Round> GetShuffleRound() { return _shuffle_round; }

      /**
       * Xor operator for QByteArrays
       * @param dst the destination byte array
       * @param t1 lhs of the xor operation
       * @param t2 rhs of the xor operation
       */
      static void Xor(QByteArray &dst, const QByteArray &t1, const QByteArray &t2);

      inline virtual const QVector<int> &GetBadMembers() const
      {
        return _bad_members;
      }

    protected:
      /**
       * Returns the ShuffleSink to access serialized descriptors
       */
      const BufferSink &GetShuffleSink() const
      {
        return _shuffle_sink;
      }

      /**
       * Sets the bad member vector
       * @param bad_members the set of bad members
       */
      void SetBadMembers(const QVector<int> &bad_members)
      {
        _bad_members = bad_members;
      }

    private:
      /**
       * Returns the data for sending in the shuffle round
       * @param max maximum amount of bytes to return
       * @returns the descriptor and false
       */
      virtual QPair<QByteArray, bool> GetShuffleData(int max) = 0;

      /**
       * Called when the shuffle finished
       */
      virtual void ShuffleFinished() = 0;

      /**
       * Pointer to Called when it is time to sgenerate the anon key and dh
       */
      BulkGetDataCallback _get_shuffle_data;

      /**
       * Holds the shuffle round
       */
      QSharedPointer<Round> _shuffle_round;

      /**
       * Stores the output of the shuffle
       */
      BufferSink _shuffle_sink;

      /**
       * List of bad nodes by group index
       */
      QVector<int> _bad_members;

      /**
       * Handle a data message from a remote peer
       * @param notification message from a remote peer
       */
      virtual void IncomingDataSpecial(const Request &) { }

    private slots:
      /**
       * Called when the descriptor shuffle ends
       */
      void SlotShuffleFinished() { ShuffleFinished(); }
  };

  template <typename B, typename S> QSharedPointer<Round> TCreateBulkRound(
      const Round::Group &group, const Round::PrivateIdentity &ident,
      const Connections::Id &round_id,
      QSharedPointer<Connections::Network> network,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<Round> round(new B(group, ident, round_id, network,
          get_data, &TCreateRound<S>));
    round->SetSharedPointer(round);
    return round;
  }
}
}

#endif
