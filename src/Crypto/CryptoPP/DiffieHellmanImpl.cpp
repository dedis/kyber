#ifdef CRYPTOPP

#include "Crypto/DiffieHellman.hpp"
#include "cryptopp/dh.h"
#include "Helper.hpp"

namespace Dissent {
namespace Crypto {
  class DiffieHellmanImpl : public IDiffieHellmanImpl {
    public:
      DiffieHellmanImpl(const QByteArray &data, bool seed)
      {
        Init(data, seed);
      }

      virtual QByteArray GetSharedSecret(const QByteArray &remote_pub) const
      {
        QByteArray shared = QByteArray(m_dh_params.AgreedValueLength(), 0);

        bool valid = m_dh_params.Agree(reinterpret_cast<byte *>(shared.data()),
            reinterpret_cast<const byte *>(m_private_key.data()),
            reinterpret_cast<const byte *>(remote_pub.data()));

        if(!valid) {
          shared.clear();
        }

        return shared;
      }

      virtual QByteArray GetPublicComponent() const
      {
        return m_public_key;
      }

      virtual QByteArray GetPrivateComponent() const
      {
        return m_private_key;
      }

    private:
      void Init(const QByteArray &data, bool seed)
      {
        m_dh_params.AccessGroupParameters().Initialize(
            ToCppInteger(DiffieHellman::GetPInt()),
            ToCppInteger(DiffieHellman::GetQInt()),
            ToCppInteger(DiffieHellman::GetGInt()));

        m_public_key = QByteArray(m_dh_params.PublicKeyLength(), 0);
        CryptoRandom rng(data);

        if(data.isEmpty() || seed) {
          m_private_key = QByteArray(m_dh_params.PrivateKeyLength(), 0);
          m_dh_params.GenerateKeyPair(GetCppRandom(rng),
              reinterpret_cast<byte *>(m_private_key.data()),
              reinterpret_cast<byte *>(m_public_key.data()));
        } else {
          m_private_key = data;
          // This DOES NOT use the rng
          m_dh_params.GeneratePublicKey(GetCppRandom(rng),
              reinterpret_cast<byte *>(m_private_key.data()),
              reinterpret_cast<byte *>(m_public_key.data()));
        }
      }

      CryptoPP::DH m_dh_params;
      QByteArray m_public_key;
      QByteArray m_private_key;
  };

  DiffieHellman::DiffieHellman(const QByteArray &data, bool seed) :
    m_data(new DiffieHellmanImpl(data, seed))
  {
  }
}
}

#endif
