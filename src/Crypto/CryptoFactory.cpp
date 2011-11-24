#include <QDebug>

#include "CppLibrary.hpp"
#include "NullLibrary.hpp"
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
    _onion(new OnionEncryptor()),
    _library_name(CryptoPP),
    _threading_type(SingleThreaded)
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
      case Null:
        _library.reset(new NullLibrary());
        break;
      default:
        qCritical() << "Invalid Library type:" << type;
        _library.reset(new CppLibrary());
    }
  }
}
}
