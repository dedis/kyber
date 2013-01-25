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

  CryptoFactory::GetInstance().SetLibrary(CryptoFactory::CryptoPP);

  Library &lib = CryptoFactory::GetInstance().GetLibrary();

  Group group(QVector<PublicIdentity>(), Id(settings.LeaderId),
      settings.SubgroupPolicy);

  QList<QSharedPointer<Node> > nodes;

  QSharedPointer<ISink> default_sink(new DummySink());
  QSharedPointer<SinkMultiplexer> app_sink(new SinkMultiplexer());

  QSharedPointer<CommandLine> commandline;
  QSharedPointer<SignalSink> signal_sink(new SignalSink());
  app_sink->AddSink(signal_sink.data());

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
      key = QSharedPointer<AsymmetricKey>(lib.LoadPrivateKeyFromFile(settings.PrivateKey[idx]));
      qDebug() << local_id << settings.PrivateKey[idx];
      dh = QSharedPointer<DiffieHellman>(lib.CreateDiffieHellman());
    } else {
      QByteArray id = local_id.GetByteArray();
      key = QSharedPointer<AsymmetricKey>(lib.GeneratePrivateKey(id));
      dh = QSharedPointer<DiffieHellman>(lib.GenerateDiffieHellman(id));
    }

    nodes.append(create(PrivateIdentity(local_id, key, key, dh, super_peer),
          group, local, remote, (idx == 0 ? app_sink.dynamicCast<ISink>() : default_sink),
          settings.SessionType, settings.AuthMode, keys));
    local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
  }

  QScopedPointer<WebServer> ws;
  QScopedPointer<SessionEntryTunnel> tun_entry;
  QScopedPointer<SessionExitTunnel> tun_exit;

  if(settings.Console) {
    commandline = QSharedPointer<CommandLine>(new CommandLine(nodes));
    QObject::connect(&qca, SIGNAL(aboutToQuit()), commandline.data(), SLOT(Stop()));
    commandline->Start();
    app_sink->AddSink(commandline.data());
  }

  if(settings.WebServer) {
    ws.reset(new WebServer(settings.WebServerUrl));

    /* Stop Web server when application is about to quit */
    QObject::connect(&qca, SIGNAL(aboutToQuit()), ws.data(), SLOT(Stop()));

    /* When the web server stops, quit the application */
    QObject::connect(ws.data(), SIGNAL(Stopped()), &qca, SLOT(quit()));

    QSharedPointer<GetMessagesService> get_messages(new GetMessagesService());
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_messages.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
    ws->AddRoute(QHttpRequest::HTTP_GET, "/session/messages", get_messages);

    QSharedPointer<GetFileService> get_webpage(new GetFileService("index.html"));
    ws->AddRoute(QHttpRequest::HTTP_GET, "/web", get_webpage);

    QSharedPointer<GetDirectoryService> get_dir(new GetDirectoryService("webpath"));
    ws->AddRoute(QHttpRequest::HTTP_GET, "/dir", get_dir);

    QSharedPointer<SessionService> session_serv(new SessionService(nodes[0]->GetSessionManager()));
    ws->AddRoute(QHttpRequest::HTTP_GET, "/session", session_serv);

    QSharedPointer<SendMessageService> send_message(new SendMessageService(nodes[0]->GetSessionManager()));
    ws->AddRoute(QHttpRequest::HTTP_POST, "/session/send", send_message);

    ws->Start();
  }
  
  if(settings.EntryTunnel) {
    tun_entry.reset(new SessionEntryTunnel(settings.EntryTunnelUrl,
          nodes[0]->GetSessionManager(),
          nodes[0]->GetOverlay()->GetRpcHandler()));
  }
  
  if(settings.ExitTunnel) {
    tun_exit.reset(new SessionExitTunnel(nodes[0]->GetSessionManager(),
          nodes[0]->GetNetwork(), settings.ExitTunnelProxyUrl));

    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        tun_exit.data(), SLOT(IncomingData(const QByteArray&)));
  }

  foreach(QSharedPointer<Node> node, nodes) {
    QObject::connect(&qca, SIGNAL(aboutToQuit()),
        node.data()->GetOverlay().data(), SLOT(CallStop()));
    node->GetOverlay()->Start();
  }

  return QCoreApplication::exec();
}
