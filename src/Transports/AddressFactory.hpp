#ifndef DISSENT_TRANSPORTS_ADDRESS_FACTORY_H_GUARD
#define DISSENT_TRANSPORTS_ADDRESS_FACTORY_H_GUARD

#include <QHash>

#include "Address.hpp"

namespace Dissent {
namespace Transports {
  /**
   * Creates an Address instance given a url
   */
  class AddressFactory {
    public:
      static AddressFactory &GetInstance();

      typedef const Address (*CreateCallback) (const QUrl &url);
      typedef const Address (*AnyCallback) ();

      void AddCreateCallback(const QString &type, CreateCallback cb);
      const Address CreateAddress(const QString &surl) const;
      const Address CreateAddress(const QUrl &url) const;

      void AddAnyCallback(const QString &type, AnyCallback cb);
      const Address CreateAny(const QString &type) const;

    private:
      QHash<QString, CreateCallback> _type_to_create;
      QHash<QString, AnyCallback> _type_to_any;

      /**
       * No inheritance, this is a singleton object
       */
      explicit AddressFactory();

      /**
       * No copying of singleton objects
       */
      Q_DISABLE_COPY(AddressFactory)
  };
}
}

#endif
