#include <QCoreApplication>
#include <QDebug>

#include "Dissent.hpp"

int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QStringList args = QCoreApplication::arguments();

  if(args.count() < 2) {
    qCritical() << "Usage:" << args[0] << "settings.conf";
    return -1;
  }

  Settings settings(args[1]);
  if(!settings.IsValid()) {
    qCritical() << settings.GetError();
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

  Library *lib = CryptoFactory::GetInstance().GetLibrary();

  Group group(QVector<GroupContainer>(), Id(settings.LeaderId),
      settings.SubgroupPolicy);

  QList<QSharedPointer<Node> > nodes;

  QSharedPointer<ISink> default_sink(new DummySink());
  QSharedPointer<ISink> app_sink = default_sink;

  if(settings.Console) {
    app_sink = QSharedPointer<CommandLine>(new CommandLine(nodes));
  } else if(settings.WebServer) {
    app_sink = QSharedPointer<SignalSink>(new SignalSink());
  }

  Id local_id = (settings.LocalId == Id::Zero()) ? Id() : settings.LocalId;
  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  if(settings.DemoMode) {
    QByteArray id = local_id.GetByteArray();
    key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
    dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
  } else {
    qFatal("Only DemoMode supported at this time;");
  }

  nodes.append(Node::CreateBasicGossip(Credentials(local_id, key, dh), group,
        local, remote, app_sink, settings.SessionType));

  for(int idx = 1; idx < settings.LocalNodeCount; idx++) {
    Id local_id;
    local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());

    QSharedPointer<AsymmetricKey> key;
    QSharedPointer<DiffieHellman> dh;

    if(settings.DemoMode) {
      QByteArray id = local_id.GetByteArray();
      key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
      dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
    } else {
      qFatal("Only DemoMode supported at this time;");
    }

    nodes.append(Node::CreateBasicGossip(Credentials(local_id, key, dh), group,
          local, remote, default_sink, settings.SessionType));
  }

  QScopedPointer<WebServer> ws;

  if(settings.Console) {
    QSharedPointer<CommandLine> cl = app_sink.dynamicCast<CommandLine>();
    QObject::connect(&qca, SIGNAL(aboutToQuit()), cl.data(), SLOT(Stop()));
    cl->Start();
  } else if(settings.WebServer) {
    ws.reset(new WebServer(settings.WebServerUrl));

    /* Stop Web server when application is about to quit */
    QObject::connect(&qca, SIGNAL(aboutToQuit()), ws.data(), SLOT(Stop()));

    /* When the web server stops, quit the application */
    QObject::connect(ws.data(), SIGNAL(Stopped()), &qca, SLOT(quit()));

    QSharedPointer<SignalSink> signal_sink = app_sink.dynamicCast<SignalSink>();

    QSharedPointer<GetMessagesService> get_messages_sp(new GetMessagesService());
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_messages_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages", get_messages_sp);

    QSharedPointer<GetFileService> get_webpage_sp(new GetFileService("index.html"));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/web", get_webpage_sp);

  nodes.append(Node::CreateBasicGossip(Credentials(local_id, key, dh), group,
        local, remote, app_sink, settings.SessionType));
    QSharedPointer<RoundIdService> round_id_sp(new RoundIdService(nodes[0]->GetSessionManager()));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/round/id", round_id_sp);

    QSharedPointer<SessionIdService> session_id_sp(new SessionIdService(nodes[0]->GetSessionManager()));
    ws->AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/id", session_id_sp);

    QSharedPointer<SendMessageService> send_message_sp(new SendMessageService(nodes[0]->GetSessionManager()));
    ws->AddRoute(HttpRequest::METHOD_HTTP_POST, "/session/send", send_message_sp);

    ws->Start();
  }

  foreach(QSharedPointer<Node> node, nodes) {
    QObject::connect(&qca, SIGNAL(aboutToQuit()),
        node.data()->GetOverlay().data(), SLOT(CallStop()));
    node->GetOverlay()->Start();
  }

  return QCoreApplication::exec();
}
