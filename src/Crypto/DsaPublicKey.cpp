#include <QDataStream>
#include <QDebug>
#include "CryptoRandom.hpp"
#include "DsaPublicKey.hpp"

namespace Dissent {
namespace Crypto {
  DsaPublicKey::DsaPublicKey(BaseDsaPublicKeyImpl *key) : AsymmetricKey(key)
  {
  }

  bool DsaPublicKey::InGroup(const QByteArray &encrypted) const
  {
    QDataStream stream(encrypted);
    Integer shared, enc;
    stream >> shared >> enc;
    return InGroup(GetKey(), shared) && InGroup(GetKey(), enc);
  }

  bool DsaPublicKey::InGroup(const BaseDsaPublicKeyImpl *key, const Integer &test)
  {
    return (test < key->GetModulus()) &&
      (test.Pow(key->GetSubgroupOrder(), key->GetModulus()) == 1);
  }

  bool DsaPublicKey::Encode(const BaseDsaPublicKeyImpl *key,
      const QByteArray &data, Integer &encoded)
  {
    if(2 * key->GetSubgroupOrder() + 1 != key->GetModulus()) {
      Integer value(data);
      if(InGroup(key, value)) {
        encoded = value;
        return true;
      }
      qWarning() << "Cannot encode elements with this key";
      return false;
    }
  
    int can_store = key->GetSubgroupOrder().GetByteCount() - 4;
    if(can_store < data.size()) {
      qWarning() << "Too large to store:" << can_store << data.size();
      return false;
    }
    
    // Add initial 0xff byte and trailing 0x00 byte
    QByteArray padded;
    padded.append(0xff);
    padded.append(data);
    padded.append(static_cast<char>(0x00));
    padded.append(0xff);

    // Change byte of padded string until the
    // integer represented by the byte arry is a quadratic
    // residue. We need to be sure that every plaintext
    // message is a quadratic residue modulo p
    const int last = padded.count() - 2;
  
    for(unsigned char pad=0x00; pad < 0xff; pad++) {
      padded[last] = pad;
  
      Integer value = Integer(padded);
      if(InGroup(key, value)) {
        encoded = value;
        return true;
      }
    }
      
    qWarning() << "Unable to encode";
    return false;
  } 
  
  bool DsaPublicKey::Decode(const BaseDsaPublicKeyImpl *key,
      const Integer &value, QByteArray &decoded)
  {
    if(!InGroup(key, value)) {
      qCritical() << "Not in group!";
      return false;
    }

    QByteArray data = value.GetByteArray();
    if(static_cast<unsigned char>(data.at(0)) == 0xff &&
        static_cast<unsigned char>(data.at(data.size() - 1)) == 0xff
        && data.count() >= 3)
    {
      decoded = data.mid(1, data.count() - 3);
    } else {
      decoded = data;
    }

    return true;
  }

  QByteArray DsaPublicKey::DefaultEncrypt(const BaseDsaPublicKeyImpl * const key,
    const QByteArray &data)
  {
    Integer encoded;
    if(!Encode(key, data, encoded)) {
      qWarning() << "Unable to encrypt due to key limitations";
      return QByteArray();
    }

    Integer secret = CryptoRandom().GetInteger(2, key->GetSubgroupOrder());
    Integer shared = key->GetGenerator().Pow(secret, key->GetModulus());
    Integer encrypted = encoded.Multiply(key->GetPublicElement().
        Pow(secret, key->GetModulus()), key->GetModulus());

    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << shared << encrypted;
    return out;
  }

  QByteArray DsaPublicKey::SeriesEncrypt(const QVector<DsaPublicKey> &keys,
          const QByteArray &data)
  {
    if(keys.size() == 0) {
      qCritical() << "Attempting to encrypt with 0 keys";
      return QByteArray();
    }

    Integer encoded;
    const DsaPublicKey &first = keys[0];
    if(!Encode(first.GetKey(), data, encoded)) {
      qWarning() << "Unable to encrypt due to key limitations";
      return QByteArray();
    }

    Integer modulus = first.GetModulus();
    Integer generator = first.GetGenerator();
    Integer subgroup = first.GetSubgroupOrder();

    Integer encrypted = 1;

    foreach(const DsaPublicKey &key, keys) {
      if(key.GetPublicElement().Pow(subgroup, modulus) != 1) {
        qDebug() << "Invalid key";
      }
      
      encrypted = encrypted.Multiply(key.GetPublicElement(), modulus);
    }
      
    Integer secret = CryptoRandom().GetInteger(2, first.GetSubgroupOrder());
    Integer shared = generator.Pow(secret, modulus);

    encrypted = encrypted.Pow(secret, modulus);
    encrypted = encoded.Multiply(encrypted, modulus);
      
    QByteArray out;
    QDataStream stream(&out, QIODevice::WriteOnly);
    stream << shared << encrypted;
    return out;
  }

  QDataStream &operator<<(QDataStream &stream, const DsaPublicKey &key)
  {
    stream << key.GetByteArray();
    return stream;
  }

  QDataStream &operator>>(QDataStream &stream, DsaPublicKey &key)
  {
    QByteArray bkey;
    stream >> bkey;
    key = DsaPublicKey(bkey, false);
    return stream;
  }
}
}
