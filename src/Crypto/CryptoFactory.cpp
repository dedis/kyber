#include <QDebug>

#include "CppLibrary.hpp"
#include "CryptoFactory.hpp"
#include "ThreadedOnionEncryptor.hpp"

namespace Dissent {
namespace Crypto {
  CryptoFactory &CryptoFactory::GetInstance()
  {
    static CryptoFactory cp;
    return cp;
  }

  CryptoFactory::CryptoFactory() :
    _library(new CppLibrary()),
    _onion(new OnionEncryptor())
  {
  }

  void CryptoFactory::SetThreading(ThreadingType type)
  {
    switch(type) {
      case MultiThreaded:
        _onion.reset(new ThreadedOnionEncryptor());
        break;
      case SingleThreaded:
        _onion.reset(new OnionEncryptor());
        break;
      default:
        qCritical() << "Invalid threading type:" << type;
        _onion.reset(new OnionEncryptor());
    }
  }

  void CryptoFactory::SetLibrary(LibraryName type)
  {
    switch(type) {
      case CryptoPP:
        _library.reset(new CppLibrary());
        break;
      default:
        qCritical() << "Invalid Library type:" << type;
        _library.reset(new CppLibrary());
    }
  }
}
}
