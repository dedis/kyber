#ifdef CRYPTOPP
#include <QDebug>
#include <cryptopp/queue.h>
#include "Crypto/CryptoRandom.hpp"
#include "Crypto/DsaPrivateKey.hpp"
#include "DsaPublicKeyImpl.hpp"
#include "Helper.hpp"

namespace Dissent {
namespace Crypto {
  class CppDsaPrivateKeyImpl : public BaseDsaPrivateKeyImpl,
      public CppDsaPublicKeyImpl {
    public:
      CppDsaPrivateKeyImpl(const Integer &modulus, const Integer &subgroup,
          const Integer &generator, const Integer &private_exponent) :
        CppDsaPublicKeyImpl(new KeyBase::PrivateKey()),
        m_public_key(new KeyBase::PublicKey())
      {
        if(private_exponent == 0) {
          CryptoRandom rand;
          GetDsaPrivateKey()->Initialize(GetCppRandom(rand),
              ToCppInteger(modulus), ToCppInteger(subgroup),
              ToCppInteger(generator));
        } else {
          GetDsaPrivateKey()->Initialize(ToCppInteger(modulus),
              ToCppInteger(subgroup), ToCppInteger(generator),
              ToCppInteger(private_exponent));
        }
        GetDsaPrivateKey()->MakePublicKey(*m_public_key);
        m_valid = true;
      }

      CppDsaPrivateKeyImpl(const QByteArray &data, bool seed) :
        CppDsaPublicKeyImpl(new KeyBase::PrivateKey()),
        m_public_key(new KeyBase::PublicKey())
      {
        if(seed) {
          CryptoRandom rand(data);
          GetDsaPrivateKey()->GenerateRandomWithKeySize(GetCppRandom(rand),
              DsaPrivateKey::DefaultKeySize());
        } else {
          CryptoPP::ByteQueue queue;
          queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

          try {
            GetDsaPrivateKey()->Load(queue);
          } catch (std::exception &e) {
            qWarning() << "In CppPublicKey::InitFromByteArray: " << e.what();
            m_valid = false;
            return;
          }
        }
        GetDsaPrivateKey()->MakePublicKey(*m_public_key);
        m_valid = true;
      }

      CppDsaPrivateKeyImpl(const QByteArray &seed, int modulus, int subgroup) :
        CppDsaPublicKeyImpl(new KeyBase::PrivateKey()),
        m_public_key(new KeyBase::PublicKey())
      {
        int actual_modulus = DsaPrivateKey::GetNearestModulus(modulus);
        subgroup = (subgroup == -1) ? DsaPrivateKey::DefaultSubgroup(modulus) : subgroup;
        if(modulus <= subgroup) {
          qFatal("Subgroup should be < Modulus");
        }
        if(modulus - 1 == subgroup) {
          subgroup = actual_modulus - 1;
        }
          
        CryptoRandom rand(seed);
        GetDsaPrivateKey()->GenerateRandom(GetCppRandom(rand),
            CryptoPP::MakeParameters
              (CryptoPP::Name::ModulusSize(), actual_modulus)
              (CryptoPP::Name::SubgroupOrderSize(), subgroup));
        GetDsaPrivateKey()->MakePublicKey(*m_public_key);
        m_valid = true;
      }

      virtual QByteArray GetByteArray() const
      {
        if(!IsValid()) {
          return QByteArray();
        }

        return CppGetByteArray(*GetDsaPrivateKey());
      }

      virtual QByteArray Sign(const QByteArray &data) const
      {
        if(!IsValid()) {
          qCritical() << "Trying to sign with an invalid key";
          return QByteArray();
        }

        KeyBase::Signer signer(*GetDsaPrivateKey());
        QByteArray sig(signer.MaxSignatureLength(), 0);
        CryptoRandom rand;
        signer.SignMessage(GetCppRandom(rand), reinterpret_cast<const byte *>(data.data()),
            data.size(), reinterpret_cast<byte *>(sig.data()));
        return sig;
      }

      virtual QByteArray Decrypt(const QByteArray &data) const
      {
        return DsaPrivateKey::DefaultDecrypt(this, data);
      }

      virtual Integer GetPrivateExponent() const
      {
        return FromCppInteger(GetDsaPrivateKey()->GetPrivateExponent());
      }

    protected:
      virtual KeyBase::PublicKey *GetDsaPublicKey() const
      {
        return m_public_key;
      }

      KeyBase::PrivateKey *GetDsaPrivateKey() const
      {
        return dynamic_cast<KeyBase::PrivateKey *>(m_key);
      }

    private:
      KeyBase::PublicKey *m_public_key;
  };

  DsaPrivateKey::DsaPrivateKey(const Integer &modulus, const Integer &subgroup,
          const Integer &generator, const Integer &private_exponent) :
    DsaPublicKey(new CppDsaPrivateKeyImpl(modulus, subgroup, generator, private_exponent))
  {
  }

  DsaPrivateKey::DsaPrivateKey(const QByteArray &data, bool seed) :
    DsaPublicKey(new CppDsaPrivateKeyImpl(data, data.size() == 0 ? true : seed))
  {
  }

  DsaPrivateKey::DsaPrivateKey(const QByteArray &seed, int modulus, int subgroup) :
    DsaPublicKey(new CppDsaPrivateKeyImpl(seed, modulus, subgroup))
  {
  }

  DsaPrivateKey::DsaPrivateKey(const QString &file) :
    DsaPublicKey(new CppDsaPrivateKeyImpl(AsymmetricKey::ReadFile(file), false))
  {
  }
}
}

#endif
