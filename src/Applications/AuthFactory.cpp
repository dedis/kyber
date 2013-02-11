#include "Crypto/LRSPrivateKey.hpp"
#include "Crypto/LRSPublicKey.hpp"
#include "Identity/Authentication/IAuthenticate.hpp"
#include "Identity/Authentication/IAuthenticator.hpp"
#include "Identity/Authentication/LRSAuthenticate.hpp"
#include "Identity/Authentication/LRSAuthenticator.hpp"
#include "Identity/Authentication/NullAuthenticate.hpp"
#include "Identity/Authentication/NullAuthenticator.hpp"
#include "Identity/Authentication/PreExchangedKeyAuthenticate.hpp"
#include "Identity/Authentication/PreExchangedKeyAuthenticator.hpp"
#include "Identity/Authentication/TwoPhaseNullAuthenticate.hpp"

#include "AuthFactory.hpp"
#include "Node.hpp"

using namespace Dissent::Identity::Authentication;
using Dissent::Crypto::AsymmetricKey;
using Dissent::Crypto::DsaPrivateKey;
using Dissent::Crypto::DsaPublicKey;
using Dissent::Crypto::LRSPrivateKey;
using Dissent::Crypto::LRSPublicKey;

namespace Dissent {
namespace Applications {
  IAuthenticator *AuthFactory::CreateAuthenticator(Node *node, AuthType type,
      const QSharedPointer<KeyShare> &keys)
  {
    switch(type) {
      case LRS_AUTH:
      {
        QVector<DsaPublicKey> public_keys;
        foreach(const QSharedPointer<AsymmetricKey> &key, *keys) {
          QSharedPointer<DsaPublicKey> dkey = key.dynamicCast<DsaPublicKey>();
          if(!dkey) {
            continue;
          }
          public_keys.append(DsaPublicKey(*dkey));
        }

        QSharedPointer<LRSPublicKey> lrs(
            new LRSPublicKey(public_keys, QByteArray()));
        return new LRSAuthenticator(lrs);
      }

      case NULL_AUTH:
      case TWO_PHASE_NULL_AUTH:
      {
        return new NullAuthenticator();
      }

      case PRE_EXCHANGED_KEY_AUTH:
      {
        return new PreExchangedKeyAuthenticator(node->GetPrivateIdentity(), keys);
      }

      default:
        qFatal("Invalid auth type");
    }
    return 0;
  }

  IAuthenticate *AuthFactory::CreateAuthenticate(Node *node, AuthType type,
      const QSharedPointer<KeyShare> &keys)
  {
    switch(type) {
      case LRS_AUTH:
      {
        QVector<DsaPublicKey> public_keys;
        foreach(const QSharedPointer<AsymmetricKey> &key, *keys) {
          QSharedPointer<DsaPublicKey> dkey = key.dynamicCast<DsaPublicKey>();
          if(!dkey) {
            continue;
          }
          public_keys.append(DsaPublicKey(*dkey));
        }

        QSharedPointer<LRSPrivateKey> lrs(
            new LRSPrivateKey(
              DsaPrivateKey(*node->GetPrivateIdentity().GetSigningKey().dynamicCast<DsaPrivateKey>()),
              public_keys,
              QByteArray()));

        return new LRSAuthenticate(node->GetPrivateIdentity(), lrs);
      }

      case NULL_AUTH:
      {
        return new NullAuthenticate(node->GetPrivateIdentity());
      }

      case PRE_EXCHANGED_KEY_AUTH:
      {
        QString leader = node->GetGroup().GetLeader().ToString();
        if(keys->Contains(leader)) {
          return new PreExchangedKeyAuthenticate(
              node->GetPrivateIdentity(), keys->GetKey(leader));
        } else {
          qFatal("Cannot find leader key");
          return 0;
        }
      }

      case TWO_PHASE_NULL_AUTH:
      {
        return new TwoPhaseNullAuthenticate(node->GetPrivateIdentity());
      }

      default:
        qFatal("Invalid auth type");
    }
    return 0;
  }
}
}
