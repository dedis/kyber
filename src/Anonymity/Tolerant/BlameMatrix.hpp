#ifndef DISSENT_ANONYMITY_TOLERANT_BLAME_MATRIX_H_GUARD
#define DISSENT_ANONYMITY_TOLERANT_BLAME_MATRIX_H_GUARD

#include <QBitArray>
#include <QByteArray>
#include <QPair>
#include <QList>
#include <QVector>

#include "Accusation.hpp"
#include "Conflict.hpp"

namespace Dissent {
namespace Anonymity {
namespace Tolerant {

  /**
   * BlameMatrix uses a combination of alibi data (sent by other nodes)
   * and message history data (stored by this node) to determine which
   * nodes sent discordant random strings in a given bit position.
   */
  class BlameMatrix {

    public:

      /**
       * A struct holding two bits -- the bit that the user sent
       * and the bit that the server sent
       */
      struct bit_pair {
        bool user_bit;
        bool server_bit;
      };

      /** 
       * Constructor.
       * @param number of users
       * @param number of servers
       */
      BlameMatrix(uint num_users, uint num_servers);

      /**
       * Add the user's alibi data to the blame matrix
       * @param index of the user
       * @param bit array indicating the bit the user shared
       *        with each server
       */
      void AddUserAlibi(uint user_idx, const QBitArray &bits);

      /**
       * Add the server's alibi data to the blame matrix
       * @param index of the server
       * @param bit array indicating the bit the server shared
       *        with each user
       */
      void AddServerAlibi(uint server_idx, const QBitArray &bits);

      /**
       * Add this node's history of which bit a user submitted
       * as output for the given bit position
       * @param index of the user
       * @param bit that the user sent
       */
      void AddUserOutputBit(uint user_idx, bool bit);

      /**
       * Add this node's history of which bit a server submitted
       * as output for the given bit position
       * @param index of the server 
       * @param bit that the server sent
       */
      void AddServerOutputBit(uint server_idx, bool bit);

      /**
       * Return a vector of the indexes of bad users.
       * Any user who sends a vector of bits that do not
       * XOR to the user's true output is bad.
       */
      QVector<int> GetBadUsers() const;

      /**
       * Return a vector of the indexes of bad servers.
       * Any server who sends a vector of bits that do not
       * XOR to the server's true output is bad.
       */
      QVector<int> GetBadServers() const;

      /**
       * Get the set of conflict data objects
       * for the given slot index and accusation
       * index
       */
      QList<Conflict> GetConflicts(uint slot_idx) const;

    private:

      /** 
       * Number of group members
       */
      const uint _num_users;

      /**
       * Number of servers
       */
      const uint _num_servers;

      /** 
       * Vector of data[user][server] => (user_bit, server_bit) 
       */
      QVector<QVector<struct bit_pair> > _data;

      /**
       * Bits transmitted by the users for the corrupted bit position
       */
      QBitArray _user_output_bits;

      /**
       * Bits transmitted by the servers for the corrupted bit position
       */
      QBitArray _server_output_bits;

  };
}
}
}

#endif
