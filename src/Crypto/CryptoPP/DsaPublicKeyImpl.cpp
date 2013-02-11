#include <QDebug>
#include <cryptopp/queue.h>
#include "Crypto/DsaPrivateKey.hpp"
#include "DsaPublicKeyImpl.hpp"
#include "Helper.hpp"

namespace Dissent {
namespace Crypto {
  CppDsaPublicKeyImpl::CppDsaPublicKeyImpl(const Integer &modulus, const Integer &subgroup,
      const Integer &generator, const Integer &public_element) :
    m_key(new KeyBase::PublicKey())
  {
    GetDsaPublicKey()->Initialize(ToCppInteger(modulus),
        ToCppInteger(subgroup),
        ToCppInteger(generator),
        ToCppInteger(public_element));
    m_valid = true;
  }

  CppDsaPublicKeyImpl::CppDsaPublicKeyImpl(const QByteArray &data, bool seed) :
    m_key(new KeyBase::PublicKey())
  {
    if(seed) {
      CryptoRandom rand(data);
      KeyBase::PrivateKey key;
      key.GenerateRandomWithKeySize(GetCppRandom(rand),
          DsaPrivateKey::DefaultKeySize());
      key.MakePublicKey(*GetDsaPublicKey());
    } else {
      CryptoPP::ByteQueue queue;
      queue.Put2(reinterpret_cast<const byte *>(data.data()), data.size(), 0, true);

      try {
        GetDsaPublicKey()->Load(queue);
      } catch (std::exception &e) {
        qWarning() << "In DsaPublicKey::DsaPublicKey: " << e.what();
        m_valid = false;
        return;
      }
    }
    m_valid = true;
  }

  CppDsaPublicKeyImpl::CppDsaPublicKeyImpl(Key *key, bool validate) :
    m_key(key), m_valid(validate)
  {
  }

  CppDsaPublicKeyImpl::~CppDsaPublicKeyImpl()
  {
    if(!m_key) {
      return;
    }

    KeyBase::PrivateKey *pri_key = dynamic_cast<KeyBase::PrivateKey *>(m_key);
    if(pri_key) {
      delete pri_key;
    } else {
      KeyBase::PublicKey *pub_key = dynamic_cast<KeyBase::PublicKey *>(m_key);
      delete pub_key;
    }
  }

  bool CppDsaPublicKeyImpl::IsValid() const
  {
    return m_valid;
  }

  int CppDsaPublicKeyImpl::GetKeySize() const
  {
    return GetModulus().GetBitCount();
  }

  int CppDsaPublicKeyImpl::GetSignatureLength() const
  {
    KeyBase::Verifier verifier(*GetDsaPublicKey());
    return verifier.SignatureLength();
  }

  bool CppDsaPublicKeyImpl::SupportsEncryption() const
  {
    return false;
  }

  bool CppDsaPublicKeyImpl::SupportsVerification() const
  {
    return true;
  }

  QSharedPointer<AsymmetricKey> CppDsaPublicKeyImpl::GetPublicKey() const
  {
    if(!IsValid()) {
      return QSharedPointer<AsymmetricKey>();
    }

    return QSharedPointer<AsymmetricKey>(
        new DsaPublicKey(new CppDsaPublicKeyImpl(
            new KeyBase::PublicKey(*GetDsaPublicKey()), true)));
  }

  QByteArray CppDsaPublicKeyImpl::GetByteArray() const
  {
    if(!IsValid()) {
      return QByteArray();
    }

    return CppGetByteArray(*GetDsaPublicKey());
  }

  QByteArray CppDsaPublicKeyImpl::Sign(const QByteArray &) const
  {
    qWarning() << "In DsaPublicKey::Sign: Attempting to sign with a public key";
    return QByteArray();
  }

  bool CppDsaPublicKeyImpl::Verify(const QByteArray &data, const QByteArray &sig) const
  {
    if(!IsValid()) {
      return false;
    }

    KeyBase::Verifier verifier(*GetDsaPublicKey());
    return verifier.VerifyMessage(reinterpret_cast<const byte *>(data.data()),
        data.size(), reinterpret_cast<const byte *>(sig.data()), sig.size());
  }

  QByteArray CppDsaPublicKeyImpl::Encrypt(const QByteArray &data) const
  {
    return DsaPublicKey::DefaultEncrypt(this, data);
  }

  QByteArray CppDsaPublicKeyImpl::Decrypt(const QByteArray &) const
  {
    qWarning() << "In DsaPublicKey::Decrypt: Attempting to decrypt with a public key";
    return QByteArray();
  }

  Integer CppDsaPublicKeyImpl::GetGenerator() const
  {
    return FromCppInteger(GetDsaPublicKey()->GetGroupParameters().GetGenerator());
  }

  Integer CppDsaPublicKeyImpl::GetModulus() const
  {
    return FromCppInteger(GetDsaPublicKey()->GetGroupParameters().GetModulus());
  }

  Integer CppDsaPublicKeyImpl::GetPublicElement() const
  {
    return FromCppInteger(GetDsaPublicKey()->GetPublicElement());
  }

  Integer CppDsaPublicKeyImpl::GetSubgroupOrder() const
  {
    return FromCppInteger(GetDsaPublicKey()->GetGroupParameters().GetSubgroupOrder());
  }

  DsaPublicKey::DsaPublicKey(const Integer &modulus, const Integer &subgroup,
      const Integer &generator, const Integer &public_element) :
    AsymmetricKey(new CppDsaPublicKeyImpl(modulus, subgroup, generator, public_element))
  {
  }

  DsaPublicKey::DsaPublicKey(const QByteArray &data, bool seed) :
    AsymmetricKey(new CppDsaPublicKeyImpl(data, data.size() == 0 ? true : seed))
  {
  }

  DsaPublicKey::DsaPublicKey(const QString &file) :
    AsymmetricKey(new CppDsaPublicKeyImpl(AsymmetricKey::ReadFile(file), false))
  {
  }
}
}
