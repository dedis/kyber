#include <QtCore>
#include "BlogDropServer.hpp"
#include "CiphertextFactory.hpp"

namespace Dissent {
namespace Crypto {
namespace BlogDrop {

  BlogDropServer::BlogDropServer(const QSharedPointer<Parameters> params, 
      const QSharedPointer<const PrivateKey> server_priv,
      const QSharedPointer<const PublicKeySet> server_pk_set,
      const QSharedPointer<const PublicKey> author_pub) :
    _phase(0),
    _params(params),
    _server_priv(server_priv),
    _server_pk_set(server_pk_set),
    _author_pub(author_pub)
  {
  }

  void BlogDropServer::ClearBin()
  {
    _client_ciphertexts.clear();
    _client_pubs.clear();
    _server_ciphertexts.clear();
    _client_pks.clear();
  }

  bool BlogDropServer::AddClientCiphertext(QByteArray in, 
      QSharedPointer<const PublicKey> pub, bool verify_proofs)
  {
    QSharedPointer<ClientCiphertext> c = CiphertextFactory::CreateClientCiphertext(_params, 
            _server_pk_set, _author_pub, in);


    bool valid;
    if(verify_proofs) {
      valid = c->VerifyProof(_phase, pub);
      if(valid) {
        _client_ciphertexts.append(c);
        _client_pubs.append(pub);
      }
    } else {
      _client_ciphertexts.append(c);
      _client_pubs.append(pub);
      valid = true;
    }

    return valid;
  }

  bool BlogDropServer::AddClientCiphertexts(const QList<QByteArray> &in, 
      const QList<QSharedPointer<const PublicKey> > &pubs, bool verify_proofs) 
  {
    if(!in.count()) qWarning() << "Added empty client ciphertext list";

    QList<QSharedPointer<const PublicKey> > pubs_out;
    QList<QSharedPointer<const ClientCiphertext> > c_out;

    bool valid;
    if(verify_proofs) {
      ClientCiphertext::VerifyProofs(_params, _server_pk_set, _author_pub, 
            _phase, pubs, in,
            c_out, pubs_out);
      _client_ciphertexts += c_out;
      _client_pubs += pubs_out;
      valid = (c_out.count() == in.count());
    } else {
      for(int i=0; i<in.count(); i++) {
        AddClientCiphertext(in[i], pubs[i], false);
      }
    }

    return valid;
  }

  QByteArray BlogDropServer::CloseBin() 
  {
    Q_ASSERT(_client_pubs.count());
    _client_pks = QSharedPointer<const PublicKeySet>(new PublicKeySet(_params, _client_pubs));

    QSharedPointer<ServerCiphertext> s = CiphertextFactory::CreateServerCiphertext(
        _params, _client_pks, _author_pub, _client_ciphertexts);
    s->SetProof(_phase, _server_priv);
    return s->GetByteArray();
  }

  bool BlogDropServer::AddServerCiphertext(const QByteArray &in,
      QSharedPointer<const PublicKey> from)
  {
    QSharedPointer<const ServerCiphertext> s = CiphertextFactory::CreateServerCiphertext(
        _params, _client_pks, _author_pub, _client_ciphertexts, in);

    bool okay = s->VerifyProof(_phase, from); 
    if(okay)
      _server_ciphertexts.append(s);

    return okay;
  }

  bool BlogDropServer::AddServerCiphertexts(const QList<QByteArray> &in, 
      const QList<QSharedPointer<const PublicKey> > &pubs) 
  {
    if(!in.count()) qWarning() << "Added empty server ciphertext list";

    QList<QSharedPointer<const ServerCiphertext> > c_out;
    ServerCiphertext::VerifyProofs(_params, _client_pks, _author_pub, _client_ciphertexts,
          _phase, pubs, in, c_out);

    _server_ciphertexts += c_out;

    return (c_out.count() == in.count());

  }

  bool BlogDropServer::RevealPlaintext(QByteArray &out) const
  {
    Plaintext m(_params);
    for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++)
    {
      //qDebug() << "client" << client_idx;
      m.Reveal(_client_ciphertexts[client_idx]->GetElements());
    }

    for(int server_idx=0; server_idx<_server_ciphertexts.count(); server_idx++)
    {
      //qDebug() << "server" << server_idx;
      m.Reveal(_server_ciphertexts[server_idx]->GetElements());
    }

    return m.Decode(out);
  }

  QSet<int> BlogDropServer::FindBadClients()
  {
    QSet<int> bad;
    for(int client_idx=0; client_idx<_client_ciphertexts.count(); client_idx++) {
      if(!_client_ciphertexts[client_idx]->VerifyProof(_phase, _client_pubs[client_idx]))
        bad.insert(client_idx);
    }

    return bad;
  }

}
}
}
