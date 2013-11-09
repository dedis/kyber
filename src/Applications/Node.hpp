#ifndef DISSENT_APPLICATIONS_NODE_H_GUARD
#define DISSENT_APPLICATIONS_NODE_H_GUARD

#include "ClientServer/Overlay.hpp"
#include "Crypto/AsymmetricKey.hpp"
#include "Crypto/KeyShare.hpp"
#include "Messaging/ISink.hpp"
#include "Session/Session.hpp"
#include "Transports/Address.hpp"

namespace Dissent {
namespace Applications {
  /**
   * A wrapper class combining an overlay, session manager, session, sink,
   * key, and whatever else might be necessary.
   */
  class Node {
    public:
      Node(const QSharedPointer<Crypto::AsymmetricKey> &key,
          const QSharedPointer<Crypto::KeyShare> &keys,
          const QSharedPointer<ClientServer::Overlay> &overlay,
          const QSharedPointer<Messaging::ISink> &sink,
          const QSharedPointer<Session::Session> &session) :
        m_key(key),
        m_keys(keys),
        m_overlay(overlay),
        m_sink(sink),
        m_session(session)
      {
      }

      ~Node()
      {
      }

      QSharedPointer<Crypto::AsymmetricKey> GetKey() const { return m_key; }
      QSharedPointer<Crypto::AsymmetricKey> GetKey() { return m_key; }

      QSharedPointer<Crypto::KeyShare> GetKeyShare() const { return m_keys; }
      QSharedPointer<Crypto::KeyShare> GetKeyShare() { return m_keys; }

      QSharedPointer<ClientServer::Overlay> GetOverlay() const { return m_overlay; }
      QSharedPointer<ClientServer::Overlay> GetOverlay() { return m_overlay; }

      QSharedPointer<Messaging::ISink> GetSink() const { return m_sink; }
      QSharedPointer<Messaging::ISink> GetSink() { return m_sink; }

      QSharedPointer<Session::Session> GetSession() const { return m_session; }
      QSharedPointer<Session::Session> GetSession() { return m_session; }

    private:
      QSharedPointer<Crypto::AsymmetricKey> m_key;
      QSharedPointer<Crypto::KeyShare> m_keys;
      QSharedPointer<ClientServer::Overlay> m_overlay;
      QSharedPointer<Messaging::ISink> m_sink;
      QSharedPointer<Session::Session> m_session;
  };
}
}

#endif
