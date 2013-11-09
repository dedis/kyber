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
#include "NeffShuffleRound.hpp"
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
  class BaseDCNetRound : public Round {
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
       * @param create_shuffle optional parameter specifying a shuffle round
       * to create, currently used for testing
       */
      explicit BaseDCNetRound(const Identity::Roster &clients,
          const Identity::Roster &servers,
          const Identity::PrivateIdentity &ident,
          const QByteArray &nonce,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          Messaging::GetDataCallback &get_data,
          CreateRound create_shuffle = &TCreateRound<NeffShuffleRound>);

      /**
       * Destructor
       */
      virtual ~BaseDCNetRound() {}

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
      typedef Messaging::BufferSink BufferSink;
      typedef Messaging::GetDataMethod<BaseDCNetRound> BulkGetDataCallback;

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

      void SetShuffleRound(const QSharedPointer<Round> &round)
      {
        _shuffle_round = round;
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

    private slots:
      /**
       * Called when the descriptor shuffle ends
       */
      void SlotShuffleFinished() { ShuffleFinished(); }
  };

  template <typename T, typename S> QSharedPointer<Round> TCreateDCNetRound(
      const Identity::Roster &clients,
      const Identity::Roster &servers,
      const Identity::PrivateIdentity &ident,
      const QByteArray &nonce,
      const QSharedPointer<ClientServer::Overlay> &overlay,
      Messaging::GetDataCallback &get_data)
  {
    QSharedPointer<T> round(new T(clients, servers, ident, nonce, overlay,
          get_data, &TCreateRound<S>));
    round->SetSharedPointer(round);
    return round;
  }
}
}

#endif
