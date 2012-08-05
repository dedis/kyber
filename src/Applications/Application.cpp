#include <QCoreApplication>
#include <QDebug>

#include "Dissent.hpp"

int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QStringList args = QCoreApplication::arguments();

  Settings settings = Settings::CommandLineParse(args);
  if(settings.Help || !settings.IsValid()) {
    QTextStream qtout(stdout, QIODevice::WriteOnly);
    qtout << "usage: " << args[0] << " [options] [settings.conf]\n\n";
    qtout << "options:\n";
    qtout << Settings::GetUsage() << "\n";
    if(!settings.Help) {
      qtout << "error: " << settings.GetError() << "\n\n";
    }
    return -1;
  }

  QList<Address> local;
  foreach(QUrl url, settings.LocalEndPoints) {
    local.append(AddressFactory::GetInstance().CreateAddress(url));
  }

  QList<Address> remote;
  foreach(QUrl url, settings.RemotePeers) {
    remote.append(AddressFactory::GetInstance().CreateAddress(url));
  }

  if(settings.Multithreading) {
    CryptoFactory::GetInstance().SetThreading(CryptoFactory::MultiThreaded);
  }

  CryptoFactory::GetInstance().SetLibrary(CryptoFactory::CryptoPPDsa);

  Library *lib = CryptoFactory::GetInstance().GetLibrary();

  Group group(QVector<PublicIdentity>(), Id(settings.LeaderId),
      settings.SubgroupPolicy);

  QList<QSharedPointer<Node> > nodes;

  QSharedPointer<ISink> default_sink(new DummySink());
  QSharedPointer<ISink> app_sink = default_sink;

  if(settings.Console) {
    app_sink = QSharedPointer<CommandLine>(new CommandLine(nodes));
  } else if(settings.WebServer || settings.EntryTunnel || settings.ExitTunnel) {
    app_sink = QSharedPointer<SignalSink>(new SignalSink());
  }

  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  Node::CreateNode create = &Node::CreateBasicGossip;
  if(settings.SubgroupPolicy == Group::ManagedSubgroup) {
    create = &Node::CreateClientServer;
  }

  bool force_super_peer = local[0].GetType().compare("buffer") == 0;
  bool super_peer = settings.SuperPeer || force_super_peer;

  QSharedPointer<KeyShare> keys(new KeyShare(settings.PublicKeys));

  for(int idx = 0; idx < settings.LocalNodeCount; idx++) {
    super_peer = settings.SuperPeer || (force_super_peer && idx < 3);
    Id local_id = settings.LocalIds.count() > idx ? settings.LocalIds[idx] : Id();

    QSharedPointer<AsymmetricKey> key;
    QSharedPointer<DiffieHellman> dh;

    if(AuthFactory::RequiresKeys(settings.AuthMode)) {
      key = QSharedPointer<AsymmetricKey>(lib->LoadPrivateKeyFromFile(settings.PrivateKey[idx]));
      qDebug() << local_id << settings.PrivateKey[idx];
      dh = QSharedPointer<DiffieHellman>(lib->CreateDiffieHellman());
    } else {
      QByteArray id = local_id.GetByteArray();
      key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
      dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
    }

    nodes.append(create(PrivateIdentity(local_id, key, dh, super_peer),
          group, local, remote, (idx == 0 ? app_sink : default_sink),
          settings.SessionType, settings.AuthMode, keys));
    local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
  }

  QScopedPointer<WebServer> ws;
  QScopedPointer<EntryTunnel> tun_entry;
  QScopedPointer<ExitTunnel> tun_exit;

  if(settings.Console) {
    QSharedPointer<CommandLine> cl = app_sink.dynamicCast<CommandLine>();
    QObject::connect(&qca, SIGNAL(aboutToQuit()), cl.data(), SLOT(Stop()));
    cl->Start();
  } else {
    QSharedPointer<SignalSink> signal_sink = app_sink.dynamicCast<SignalSink>();

    if(settings.WebServer) {
      ws.reset(new WebServer(settings.WebServerUrl));

      /* Stop Web server when application is about to quit */
      QObject::connect(&qca, SIGNAL(aboutToQuit()), ws.data(), SLOT(Stop()));

      /* When the web server stops, quit the application */
      QObject::connect(ws.data(), SIGNAL(Stopped()), &qca, SLOT(quit()));

      QSharedPointer<GetMessagesService> get_messages_sp(new GetMessagesService());
      QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
          get_messages_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
      ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages", get_messages_sp);

      QSharedPointer<GetFileService> get_webpage_sp(new GetFileService("index.html"));
      ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/web", get_webpage_sp);

      QSharedPointer<RoundIdService> round_id_sp(new RoundIdService(nodes[0]->GetSessionManager()));
      ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/round/id", round_id_sp);

      QSharedPointer<SessionIdService> session_id_sp(new SessionIdService(nodes[0]->GetSessionManager()));
      ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/id", session_id_sp);

      QSharedPointer<SendMessageService> send_message_sp(new SendMessageService(nodes[0]->GetSessionManager()));
      ws->AddRoute(HttpRequest::METHOD_HTTP_POST, "/session/send", send_message_sp);

      ws->Start();
    }
    
    if(settings.EntryTunnel) {
      tun_entry.reset(new EntryTunnel(settings.EntryTunnelUrl, nodes[0]->GetSessionManager(), 
            nodes[0]->GetOverlay()->GetRpcHandler()));

      QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
          tun_entry.data(), SLOT(DownstreamData(const QByteArray&)));

      tun_entry->Start();
    }
    
    if(settings.ExitTunnel) {
      tun_exit.reset(new ExitTunnel(nodes[0]->GetSessionManager(),
            nodes[0]->GetNetwork(), settings.ExitTunnelProxyUrl));

      QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
          tun_exit.data(), SLOT(SessionData(const QByteArray&)));

      tun_exit->Start();
    }
  }

  foreach(QSharedPointer<Node> node, nodes) {
    QObject::connect(&qca, SIGNAL(aboutToQuit()),
        node.data()->GetOverlay().data(), SLOT(CallStop()));
    node->GetOverlay()->Start();
  }

  return QCoreApplication::exec();
}
