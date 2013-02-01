
#include <QtConcurrentMap>

#include "Crypto/AbstractGroup/Element.hpp"
#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "CiphertextFactory.hpp" 
#include "ServerCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ServerCiphertext::ServerCiphertext(const QSharedPointer<const Parameters> &params,
      const QSharedPointer<const PublicKey> &author_pub, 
      int n_elms) :
    _params(params),
    _author_pub(author_pub),
    _n_elms(n_elms)
  {}

  void ServerCiphertext::VerifyProofs(
      const QSharedPointer<const Parameters> &params,
      const QSharedPointer<const PublicKeySet> &server_pk_set,
      const QSharedPointer<const PublicKey> &author_pk,
      const QList<QSharedPointer<const ClientCiphertext> > &client_ctexts,
      int phase, 
      const QList<QSharedPointer<const PublicKey> > &pubs,
      const QList<QByteArray> &c,
      QList<QSharedPointer<const ServerCiphertext> > &c_out)
  {
    Q_ASSERT(pubs.count() == c.count());

    CryptoFactory::ThreadingType tt = CryptoFactory::GetInstance().GetThreadingType();
    if(tt == CryptoFactory::SingleThreaded) {
      QList<QSharedPointer<const ServerCiphertext> > list;

      // Unpack each ciphertext
      for(int server_idx=0; server_idx<c.count(); server_idx++) {
        list.append(CiphertextFactory::CreateServerCiphertext(params, 
              server_pk_set, author_pk, client_ctexts, c[server_idx]));
      }

      // Verify each proof
      for(int idx=0; idx<c.count(); idx++) {
        if(list[idx]->VerifyProof(phase, pubs[idx])) {
          c_out.append(list[idx]);
        }
      }

    } else if(tt == CryptoFactory::MultiThreaded) {

      QList<QByteArray> ctext_bytes;
      for(int i=0; i<client_ctexts.count(); i++) {
        ctext_bytes.append(client_ctexts[i]->GetByteArray());
      }

      QList<QSharedPointer<MapData> > ms;

      // Unpack each ciphertext copying parameters to
      // avoid shared data
      for(int server_idx=0; server_idx<c.count(); server_idx++) {
        QSharedPointer<MapData> m(new MapData());
        m->params = new Parameters(*params);

        QByteArray mine;
        QDataStream stream(&mine, QIODevice::WriteOnly);
        stream << ctext_bytes;

        m->client_ciphertext_list = mine;
        m->server_pk_set = server_pk_set->GetByteArray();
        m->author_pk = author_pk->GetByteArray();
        m->server_pk = pubs[server_idx]->GetByteArray();
        m->server_ciphertext = c[server_idx];
        m->phase = phase;

        ms.append(m);
      }

      QList<bool> valid_list = QtConcurrent::blockingMapped(ms, VerifyOnce);

      for(int server_idx=0; server_idx<valid_list.count(); server_idx++) {
        if(valid_list[server_idx]) {
          c_out.append(CiphertextFactory::CreateServerCiphertext(
              params, server_pk_set, author_pk, client_ctexts, c[server_idx]));
        }
      }

    } else {
      qFatal("Unknown threading type");
    }
  }

  bool ServerCiphertext::VerifyOnce(const QSharedPointer<MapData> &m)
  {
    QSharedPointer<const Parameters> params(m->params);

    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, m->server_pk_set));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(params, m->author_pk)); 
    QSharedPointer<const PublicKey> server_pk(new PublicKey(params, m->server_pk)); 

    QList<QByteArray> client_ctexts_raw;
    QDataStream stream(m->client_ciphertext_list);
    stream >> client_ctexts_raw;

    QList<QSharedPointer<const ClientCiphertext> > client_ctexts;
    for(int i=0; i<client_ctexts_raw.count(); i++) {
      client_ctexts.append(CiphertextFactory::CreateClientCiphertext(
            params, server_pk_set, author_pk, client_ctexts_raw[i]));
    }

    QSharedPointer<const ServerCiphertext> s = CiphertextFactory::CreateServerCiphertext(
              params, server_pk_set, author_pk, client_ctexts, m->server_ciphertext);
    return s->VerifyProof(m->phase, server_pk);
  }
}
}
}
