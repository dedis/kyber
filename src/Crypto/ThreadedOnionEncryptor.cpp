#include "ThreadedOnionEncryptor.hpp"
#include <qcoreapplication.h>
#include <QtConcurrentMap>
#include "CppPrivateKey.hpp"

namespace Dissent {
namespace Crypto {
  namespace {
    /**
     * Provides a method object decrypting a single QByteArray, useful for QtConcurrent
     */
    struct Decryptor {
      Decryptor(const AsymmetricKey *key) : _key(key) {}

      typedef QByteArray result_type;

      QByteArray operator()(const QByteArray &ciphertext) const
      {
        return _key->Decrypt(ciphertext);
      }

      const AsymmetricKey *_key;
    };
  }

  ThreadedOnionEncryptor &ThreadedOnionEncryptor::GetInstance()
  {
    static ThreadedOnionEncryptor toe;
    return toe;
  }

  bool ThreadedOnionEncryptor::Decrypt(const AsymmetricKey *key,
      const QVector<QByteArray> &ciphertext, QVector<QByteArray> &cleartext,
      QVector<int> *bad) const
  {
    QFuture<QByteArray> result = QtConcurrent::mapped(ciphertext.begin(),
        ciphertext.end(), Decryptor(key));
    cleartext.clear();
    result.waitForFinished();

    bool res = true;
    int idx = -1;
    foreach(const QByteArray &data, result) {
      idx++;
      cleartext.append(data);

      if(!data.isEmpty()) {
        continue;
      }

      res = false;
      if(bad) {
        bad->append(idx);
      }
    }
    return res;
  }
}
}
