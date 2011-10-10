#include "OnionEncryptor.hpp"

namespace Dissent {
namespace Crypto {
  void Print(const QVector<QByteArray> &datas);
  OnionEncryptor &OnionEncryptor::GetInstance()
  {
    static OnionEncryptor onion_encryptor;
    return onion_encryptor;
  }

  int OnionEncryptor::Encrypt(const QVector<AsymmetricKey *> &keys,
      const QByteArray &cleartext,
      QByteArray &ciphertext,
      QVector<QByteArray> &intermediate)
  {
    QByteArray data = keys.first()->Encrypt(cleartext);
    if(data.isEmpty()) {
      return 0;
    }
    intermediate.append(data);

    if(keys.count() == 1) {
      return -1;
    }

    for(int idx = 1; idx < keys.count() - 1; idx++) {
      data = keys[idx]->Encrypt(intermediate.last());
      if(data.isEmpty()) {
        return idx;
      }
      intermediate.append(data);
    }

    ciphertext = keys.last()->Encrypt(intermediate.last());
    if(ciphertext.isEmpty()) {
      return keys.count() - 1;
    }

    return -1;
  }

  int OnionEncryptor::Decrypt(AsymmetricKey *key,
      const QVector<QByteArray> &ciphertext,
      QVector<QByteArray> &cleartext)
  {
    for(int idx = 0; idx < ciphertext.count(); idx++) {
      QByteArray data = key->Decrypt(ciphertext[idx]);
      if(data.isEmpty()) {
        return idx;
      }
      cleartext.append(data);
    }

    return -1;
  }

  bool OnionEncryptor::VerifyOne(AsymmetricKey *key,
      const QVector<QByteArray> &cleartext,
      const QVector<QByteArray> &ciphertext) const
  {
    foreach(QByteArray cph, ciphertext) {
      QByteArray clr = key->Decrypt(cph);
      if(!cleartext.contains(clr)) {
        return false;
      }
    }
    return true;
  }

  bool OnionEncryptor::VerifyAll(const QVector<AsymmetricKey *> &keys,
      const QVector<QVector<QByteArray> > &onion,
      QBitArray &bad)
  {
    if(keys.count() != onion.count() - 1) {
      qWarning() << "Incorrect key to onion layers ratio: " << keys.count() <<
        ":" << onion.count();
      return false;
    }

    if(keys.count() != bad.count()) {
      bad = QBitArray(keys.count(), false);
    }

    bool res = true;
    for(int idx = 0; idx < keys.count(); idx++) {
      if(!VerifyOne(keys[idx], onion[idx], onion[idx + 1])) {
        bad[idx] = true;
        res = false;
      }
    }

    return res;
  }

  int OnionEncryptor::ReorderRandomBits(
      const QVector<QVector<QByteArray> > &in_bits,
      QVector<QVector<QByteArray> > &out_bits)
  {
    if(in_bits.isEmpty()) {
      qWarning() << "There should be at least one vector in in_bits";
      return -2;
    }

    int keys = in_bits.count();
    int msgs = in_bits[0].count();

    for(int idx = 0; idx < keys; idx++) {
      if(in_bits[idx].count() != msgs) {
        qWarning() << "Not all in_bit vectors are of the same length";
        return idx;
      }
    }

    for(int idx = 0; idx < msgs; idx++) {
      out_bits.append(QVector<QByteArray>(keys));
      for(int jdx = 0; jdx < keys; jdx++) {
        out_bits[idx][jdx] = in_bits[jdx][idx];
      }
    }
    return -1;
  }
}
}
