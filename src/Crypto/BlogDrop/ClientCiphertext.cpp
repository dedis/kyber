
#include <QtCore>

#include "Crypto/CryptoFactory.hpp"

#include "BlogDropUtils.hpp"
#include "CiphertextFactory.hpp"
#include "ClientCiphertext.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  ClientCiphertext::ClientCiphertext(const QSharedPointer<const Parameters> params, 
      const QSharedPointer<const PublicKeySet> server_pks,
      const QSharedPointer<const PublicKey> author_pub,
      int n_elms) :
    _params(params),
    _server_pks(server_pks),
    _author_pub(author_pub),
    _n_elms(n_elms)
  {
  }

  void ClientCiphertext::VerifyProofs(const QSharedPointer<const Parameters> params,
          const QSharedPointer<const PublicKeySet> server_pk_set,
          const QSharedPointer<const PublicKey> author_pk,
          int phase, 
          const QList<QSharedPointer<const PublicKey> > &pubs,
          const QList<QByteArray> &c,
          QList<QSharedPointer<const ClientCiphertext> > &c_out,
          QList<QSharedPointer<const PublicKey> > &pubs_out)
  {
    Q_ASSERT(pubs.count() == c.count());

    CryptoFactory::ThreadingType tt = CryptoFactory::GetInstance().GetThreadingType();

    if(tt == CryptoFactory::SingleThreaded) {
      QList<QSharedPointer<const ClientCiphertext> > list;

      // Unpack each ciphertext
      for(int client_idx=0; client_idx<c.count(); client_idx++) {
        list.append(CiphertextFactory::CreateClientCiphertext(params, 
              server_pk_set, author_pk, c[client_idx]));
      }

      // Verify each proof
      for(int idx=0; idx<c.count(); idx++) {
        if(list[idx]->VerifyProof(phase, pubs[idx])) {
          c_out.append(list[idx]);
          pubs_out.append(pubs[idx]);
        }
      }

    } else if(tt == CryptoFactory::MultiThreaded) {
      QList<QSharedPointer<MapData> > ms;

      // Unpack each ciphertext copying parameters to
      // avoid shared data. Each thread must have its
      // own Parameters object.
      for(int client_idx=0; client_idx<c.count(); client_idx++) {
        QSharedPointer<MapData> m(new MapData());
        m->params = new Parameters(*params);
        m->server_pk_set = server_pk_set->GetByteArray();
        m->author_pk = author_pk->GetByteArray();
        m->client_pk = pubs[client_idx]->GetByteArray();
        m->ciphertext = c[client_idx];
        m->phase = phase;
        ms.append(m);
      }

      QList<bool> valid_list = QtConcurrent::blockingMapped(ms, VerifyOnce);

      for(int client_idx=0; client_idx<valid_list.count(); client_idx++) {
        if(valid_list[client_idx]) {
          c_out.append(CiphertextFactory::CreateClientCiphertext(
                  params, server_pk_set, author_pk, c[client_idx]));
          pubs_out.append(pubs[client_idx]);
        }
      }

    } else {
      qFatal("Unknown threading type");
    }
  }

  bool ClientCiphertext::VerifyOnce(QSharedPointer<MapData> m)
  {
    QSharedPointer<const Parameters> params(m->params);
    QSharedPointer<const PublicKeySet> server_pk_set(new PublicKeySet(params, m->server_pk_set));
    QSharedPointer<const PublicKey> author_pk(new PublicKey(params, m->author_pk));
    QSharedPointer<const PublicKey> client_pk(new PublicKey(params, m->client_pk));

    QSharedPointer<const ClientCiphertext> c = CiphertextFactory::CreateClientCiphertext(params, server_pk_set,
        author_pk, m->ciphertext);

    return c->VerifyProof(m->phase, client_pk);
  }

}
}
}
