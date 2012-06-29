#ifndef DISSENT_IDENTITY_NULL_AUTHENTICATE_GUARD
#define DISSENT_IDENTITY_NULL_AUTHENTICATE_GUARD

#include <QVariant>

#include "Connections/Id.hpp"

#include "IAuthenticate.hpp"

namespace Dissent {
namespace Identity {
namespace Authentication {

  /**
   * Implements a authenticating member who expects to always return true.
   */
  class NullAuthenticate : public IAuthenticate {

    public:
      NullAuthenticate(const PrivateIdentity &ident) : _ident(ident)
      {
        QByteArray ident_arr;
        QDataStream stream(&ident_arr, QIODevice::WriteOnly);
        stream << Identity::GetPublicIdentity(ident);
        _ident_var = ident_arr;
      }

      virtual ~NullAuthenticate() {}

      /**
       * This is a single phase (register)
       */
      inline virtual bool RequireRequestChallenge() { return false; }

      /**
       * We do not need a challege.
       */
      inline virtual QVariant PrepareForChallenge()
      {
        return _ident_var;
      }

      /**
       * We do not get a challenge, so this should not be called.
       */
      inline virtual QPair<bool, QVariant> ProcessChallenge(const QVariant &)
      {
        return QPair<bool, QVariant>(true, _ident_var);
      }

      /**
       * Returns the PrivateIdentity, potentially updated
       * due to the authentication process
       */
      inline virtual PrivateIdentity GetPrivateIdentity() const
      {
        return _ident;
      }

    protected:
      PrivateIdentity _ident;
      QVariant _ident_var;
  };
}
}
}

#endif
