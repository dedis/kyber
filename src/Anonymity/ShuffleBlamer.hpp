#ifndef DISSENT_ANONYMITY_SHUFFLE_BLAMER_H_GUARD
#define DISSENT_ANONYMITY_SHUFFLE_BLAMER_H_GUARD

#include <QObject>
#include <QSharedPointer>

#include "Connections/Id.hpp"
#include "Identity/Credentials.hpp"
#include "Identity/Group.hpp"

#include "ShuffleRoundBlame.hpp"
#include "Log.hpp"

namespace Dissent {
namespace Crypto {
  class AsymmetricKey;
}

namespace Anonymity {
  /**
   * Runs through the blame data to find faulty nodes
   */
  class ShuffleBlamer {
    public:
      typedef Connections::Id Id;
      typedef Crypto::AsymmetricKey AsymmetricKey;
      typedef Identity::Credentials Credentials;
      typedef Identity::Group Group;

      /**
       * Constructors
       * @param group Group used during this round
       * @param round_id Unique round id (nonce)
       * @param logs all the incoming logs for nodes in the group
       * @param private_keys the outer private keys for nodes in the group
       */
      explicit ShuffleBlamer(const Group &group, const Id &round_id,
          const QVector<Log> &logs, const QVector<AsymmetricKey *> private_keys);

      /**
       * Deconstructor
       */
      ~ShuffleBlamer();

      /**
       * Start the blame process
       */
      void Start();

      /**
       * Returns a bit array, an index is true if the node was bad
       */
      inline const QBitArray &GetBadNodes() const { return _bad_nodes; }

      /**
       * Returns the reason(s) why a node was selected as "bad"
       * @param idx the index of the bad node
       */
      const QVector<QString> &GetReasons(int idx);

    private:
      /**
       * Sets a node as bad with the given reason
       * @param id the id of the bad node
       * @param reason the reason the node is bad
       */
      void Set(const Id &id, const QString &reason);

      /**
       * Sets a node as bad with the given reason
       * @param idx the index of the bad node
       * @param reason the reason the node is bad
       */
      void Set(int idx, const QString &reason);
      
      /**
       * Creates Shuffle rounds using the ShuffleRoundBlame for each given log
       */
      void ParseLogs();

      /**
       * Creates a ShuffleRoundBlame for the given node idx
       * @param idx the log to parse
       */
      void ParseLog(int idx);

      /**
       * Verifies that each node has the correct public keys
       */
      void CheckPublicKeys();

      /**
       * Verifies that no nodes changed the message given what was inputted into them
       */
      void CheckShuffle();

      /**
       * Compares the two vectors and returns how many byte arrays they have in common
       * @param lhs one of the vectors to compare
       * @param rhs the other vector to compare
       */
      static int CountMatches(const QVector<QByteArray> &lhs, const QVector<QByteArray> &rhs);
      void CheckVerification();

      const Group _group;
      const Group _shufflers;
      QVector<Log> _logs;
      QVector<AsymmetricKey *> _private_keys;
      QBitArray _bad_nodes;
      QVector<QVector<QString> > _reasons;
      QVector<ShuffleRoundBlame *> _rounds;
      QVector<QByteArray> _inner_data;
      bool _set;
  };
}
}

#endif
