#ifdef FAST_NEFF_SHUFFLE
#include "FastNeffKeyShuffleRound.hpp"
#else
#ifndef DISSENT_ANONYMITY_NEFF_KEY_SHUFFLE_ROUND_H_GUARD
#define DISSENT_ANONYMITY_NEFF_KEY_SHUFFLE_ROUND_H_GUARD

#include "Crypto/DsaPublicKey.hpp"
#include "NeffShuffleRound.hpp"

namespace Dissent {
namespace Anonymity {

  /**
   * Wrapper around NeffShuffleRound to make keys easier to access.
   * Also API compatible with the old NeffKeyShuffle
   */
  class NeffKeyShuffleRound : public NeffShuffleRound {
    public:
      /**
       * Constructor
       * @param group Group used during this round
       * @param ident the local nodes credentials
       * @param round_id Unique round id (nonce)
       * @param network handles message sending
       * @param get_data requests data to share during this session
       * @param bm buddy monitor
       */
      explicit NeffKeyShuffleRound(const Group &group,
          const PrivateIdentity &ident,
          const Id &round_id,
          const QSharedPointer<Network> &network,
          GetDataCallback &get_data,
          const QSharedPointer<BuddyMonitor> &bm) :
        NeffShuffleRound(group, ident, round_id, network, get_data, bm, true),
        _parsed(false), _key_index(-1) { }

      /**
       * Destructor
       */
      virtual ~NeffKeyShuffleRound() {}

      /**
       * Returns the anonymized private key
       */
      QSharedPointer<AsymmetricKey> GetKey() const
      {
        if(const_cast<NeffKeyShuffleRound *>(this)->Parse()) {
          return GetState()->private_key;
        } else {
          return QSharedPointer<AsymmetricKey>();
        }
      }

      /**
       * Returns the list of shuffled keys
       */
      QVector<QSharedPointer<AsymmetricKey> > GetKeys() const
      {
        if(const_cast<NeffKeyShuffleRound *>(this)->Parse()) {
          return _keys;
        } else {
          return QVector<QSharedPointer<AsymmetricKey> >();
        }
      }

      /**
       * Returns the index in the shuffle for the anonymized proivate key
       */
      int GetKeyIndex() const
      {
        if(const_cast<NeffKeyShuffleRound *>(this)->Parse()) {
          return _key_index;
        } else {
          return -1;
        }
      }

    private:
      bool Parse()
      {
        if(_parsed) {
          return true;
        } else if(!Successful()) {
          return false;
        }

        QSharedPointer<Crypto::DsaPublicKey> my_key(GetState()->private_key->
            GetPublicKey().dynamicCast<Crypto::DsaPublicKey>());
        Integer modulus = my_key->GetModulus();
        Integer subgroup = my_key->GetSubgroupOrder();
        Integer generator = my_key->GetGenerator();

        for(int idx = 0; idx < GetState()->cleartext.size(); idx++) {
          const QByteArray  &ct = GetState()->cleartext[idx];
          Integer public_element(ct);
          QSharedPointer<AsymmetricKey> key(new Crypto::DsaPublicKey(modulus,
                subgroup, generator, public_element));
          _keys.append(key);
          if(key == my_key) {
            _key_index = idx;
          }
        }

        _parsed = true;
        return true;
      }

      bool _parsed;
      QVector<QSharedPointer<AsymmetricKey> > _keys;
      int _key_index;
  };
}
}

#endif
#endif
