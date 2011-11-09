#ifndef DISSENT_CRYPTO_CRYPTO_FACTORY_H_GUARD
#define DISSENT_CRYPTO_CRYPTO_FACTORY_H_GUARD

#include <QScopedPointer>
#include "OnionEncryptor.hpp"
#include "Library.hpp"

namespace Dissent {
namespace Crypto {
  class CryptoFactory {
    public:
      enum ThreadingType {
        SingleThreaded,
        MultiThreaded
      };

      enum LibraryName {
        CryptoPP
      };

      /**
       * Returns a reference to the singleton
       */
      static CryptoFactory &GetInstance();

      /**
       * Sets the type of threading support
       */
      void SetThreading(ThreadingType type);

      /**
       * Sets the library used
       */
      void SetLibrary(LibraryName type);

      /**
       * Return the Onion Encryptor
       */
      inline OnionEncryptor *GetOnionEncryptor() { return _onion.data(); }

      /**
       * Return the library constructor
       */
      inline Library *GetLibrary() { return _library.data(); }

    private:
      /**
       * Library for Crypto utils
       */
      QScopedPointer<Library> _library;

      /**
       * Store a reference to the OnionEncryptor and return copies of the reference
       */
      QScopedPointer<OnionEncryptor> _onion;

      /**
       * No inheritance, this is a singleton object
       */
      CryptoFactory(); 

      /**
       * No copying of singleton objects
       */
      Q_DISABLE_COPY(CryptoFactory)
  };
}
}

#endif
