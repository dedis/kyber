#include "OnionEncryptor.hpp"

namespace Dissent {
namespace Crypto {
  OnionEncryptor &OnionEncryptor::GetInstance()
  {
    static OnionEncryptor onion_encryptor;
    return onion_encryptor;
  }

  int OnionEncryptor::Encrypt(const QVector<AsymmetricKey *> &keys,
      const QByteArray &cleartext,
      QByteArray &ciphertext,
      QVector<QByteArray> *intermediate)
  {
    ciphertext = keys.first()->Encrypt(cleartext);

    if(ciphertext.isEmpty()) {
      return 0;
    }

    if(intermediate) {
      intermediate->append(ciphertext);
    }

    if(keys.count() == 1) {
      return -1;
    }

    for(int idx = 1; idx < keys.count() - 1; idx++) {
      ciphertext = keys[idx]->Encrypt(ciphertext);

      if(ciphertext.isEmpty()) {
        return idx;
      }

      if(intermediate) {
        intermediate->append(ciphertext);
      }
    }

    ciphertext = keys.last()->Encrypt(ciphertext);

    if(ciphertext.isEmpty()) {
      return keys.count() - 1;
    }

    return -1;
  }

  bool OnionEncryptor::Decrypt(AsymmetricKey *key,
      const QVector<QByteArray> &ciphertext,
      QVector<QByteArray> &cleartext, QVector<int> *bad)
  {
    cleartext.clear();
    bool res = true;
    for(int idx = 0; idx < ciphertext.count(); idx++) {
      QByteArray data = key->Decrypt(ciphertext[idx]);
      if(data.isEmpty()) {
        res = false;
        if(bad) {
          bad->append(idx);
        }
      }
      cleartext.append(data);
    }
    return res;
  }

  void OnionEncryptor::RandomizeBlocks(QVector<QByteArray> &text)
  {
    CppRandom rand;
    for(int idx = 0; idx < text.count(); idx++) {
      int jdx = rand.GetInt(0, text.count());
      if(jdx == idx) {
        continue;
      }
      QByteArray tmp = text[idx];
      text[idx] = text[jdx];
      text[jdx] = tmp;
    }
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
