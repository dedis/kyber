#include <QDebug>

#include "CppLibrary.hpp"
#include "CppDsaLibrary.hpp"
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
    _threading_type(SingleThreaded),
    _previous(0)
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
    if(_previous != 0) {
      AsymmetricKey::DefaultKeySize = std::min(_previous,
          AsymmetricKey::DefaultKeySize);
    }

    _previous = AsymmetricKey::DefaultKeySize;
    _library_name = type;

    switch(type) {
      case CryptoPP:
        _library.reset(new CppLibrary());
        break;
      case CryptoPPDsa:
        _library.reset(new CppDsaLibrary());
        break;
      case Null:
        _library.reset(new NullLibrary());
        break;
      default:
        qCritical() << "Invalid Library type:" << type;
        _library.reset(new CppLibrary());
        _library_name = CryptoPP;
    }

    AsymmetricKey::DefaultKeySize = std::max(_library->MinimumKeySize(),
        AsymmetricKey::DefaultKeySize);
  }
}
}
