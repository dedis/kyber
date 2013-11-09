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

  QList<QSharedPointer<Node> > nodes;

  QSharedPointer<ISink> default_sink(new DummySink());
  QSharedPointer<SinkMultiplexer> app_sink(new SinkMultiplexer());

  QSharedPointer<CommandLine> commandline;
  QSharedPointer<SignalSink> signal_sink(new SignalSink());
  app_sink->AddSink(signal_sink.data());

  QSharedPointer<KeyShare> keys(new KeyShare(settings.PublicKeys));
  foreach(const Id &server, settings.ServerIds) {
    if(!keys->Contains(server.ToString())) {
      qFatal("Missing key for %s", server.ToString().toLatin1().data());
    }
  }

  QList<Address> local_end_points = settings.LocalEndPoints;

  for(int idx = 0; idx < settings.LocalNodeCount; idx++) {
    Id local_id = idx < settings.LocalId.count() ? settings.LocalId[idx] : Id();
    QSharedPointer<AsymmetricKey> key;

    QString key_path = settings.PrivateKeys + "/" + local_id.ToString();
    QFile key_file(key_path);
    if(key_file.exists()) {
      key = QSharedPointer<AsymmetricKey>(new DsaPrivateKey(key_path));
    } else {
      QByteArray id = local_id.GetByteArray();
      key = QSharedPointer<AsymmetricKey>(new DsaPrivateKey(id, true));
    }

    QSharedPointer<ISink> nsink = (idx == 0) ? app_sink.dynamicCast<ISink>() : default_sink;
    QSharedPointer<Overlay> overlay(new Overlay(local_id, local_end_points,
          settings.RemoteEndPoints, settings.ServerIds));
    overlay->SetSharedPointer(overlay);

    CreateRound create_round = RoundFactory::GetCreateRound(settings.RoundType);
    QSharedPointer<Session> session;
    if(settings.ServerIds.contains(local_id)) {
      session = MakeSession<ServerSession>(overlay, key, keys, create_round);
    } else {
      session = MakeSession<ClientSession>(overlay, key, keys, create_round);
    }
    session->SetSink(nsink.data());
    QSharedPointer<Node> node(new Node(key, keys, overlay, nsink, session));
    nodes.append(node);

    for(int idx = 0; idx < local_end_points.count(); idx++) {
      local_end_points[idx] = AddressFactory::GetInstance().
        CreateAny(local_end_points[idx].GetType());
    }
  }

  QScopedPointer<WebServer> ws;
//  QScopedPointer<SessionEntryTunnel> tun_entry;
//  QScopedPointer<SessionExitTunnel> tun_exit;

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

    QSharedPointer<SessionService> session_serv(new SessionService(nodes[0]->GetSession()));
    ws->AddRoute(QHttpRequest::HTTP_GET, "/session", session_serv);

    QSharedPointer<SendMessageService> send_message(new SendMessageService(nodes[0]->GetSession()));
    ws->AddRoute(QHttpRequest::HTTP_POST, "/session/send", send_message);

//    QSharedPointer<BuddiesService> bs(new BuddiesService(nodes[0]->GetSessionManager()));
//    ws->AddRoute(QHttpRequest::HTTP_GET, "/session/buddies", bs);

    ws->Start();
  }
  
  if(settings.EntryTunnel) {
//    tun_entry.reset(new SessionEntryTunnel(settings.EntryTunnelUrl,
//          nodes[0]->GetSessionManager(),
//          nodes[0]->GetOverlay()->GetRpcHandler()));
  }
  
  if(settings.ExitTunnel) {
//    tun_exit.reset(new SessionExitTunnel(nodes[0]->GetSessionManager(),
//          nodes[0]->GetNetwork(), settings.ExitTunnelProxyUrl));

//    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
//        tun_exit.data(), SLOT(IncomingData(const QByteArray&)));
  }

  foreach(QSharedPointer<Node> node, nodes) {
    node->GetOverlay()->Start();
    node->GetSession()->Start();
    QObject::connect(&qca, SIGNAL(aboutToQuit()),
        node.data()->GetOverlay().data(), SLOT(CallStop()));
  }

  return QCoreApplication::exec();
}
