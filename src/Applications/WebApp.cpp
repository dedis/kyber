#include <QCoreApplication>
#include <QByteArray>
#include <QDebug>

#include "../Dissent.hpp"

using namespace Dissent::Applications;
using namespace Dissent::Web::Services;

int main(int argc, char **argv)
{
  QCoreApplication qca(argc, argv);
  QStringList args = QCoreApplication::arguments();

  if(args.count() != 2) {
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

  QList<QSharedPointer<Node> > nodes;

  Id local_id;
  if(!settings.LocalId.isEmpty()) {
    local_id = Id(settings.LocalId);
  }

  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  if(settings.DemoMode) {
    QByteArray id = local_id.GetByteArray();
    key = QSharedPointer<AsymmetricKey>(lib->GeneratePrivateKey(id));
    dh = QSharedPointer<DiffieHellman>(lib->GenerateDiffieHellman(id));
  } else {
    qFatal("Only DemoMode supported at this time;");
  }

  nodes.append(QSharedPointer<Node>(new Node(Credentials(local_id, key, dh),
          local, remote, settings.GroupSize, settings.SessionType)));


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

    nodes.append(QSharedPointer<Node>(new Node(Credentials(local_id, key, dh),
            local, remote, settings.GroupSize, settings.SessionType)));
    nodes[idx]->sink = QSharedPointer<ISink>(new DummySink());
  }

  foreach(QSharedPointer<Node> node, nodes) {
    QObject::connect(&qca, SIGNAL(aboutToQuit()), &node.data()->bg, SLOT(Stop()));
    node->bg.Start();
  }

  Dissent::Web::WebServer ws(settings.WebServerHost, settings.WebServerPort);
  if(settings.WebServer) {
    /***
     * START Set up web server
     */
    QObject::connect(nodes[0].data(), SIGNAL(Ready()), &ws, SLOT(Ready()));

    /* Stop Web server when application is about to quit */
    QObject::connect(&qca, SIGNAL(aboutToQuit()), &ws, SLOT(Stop()));

    /* When the web server stops, quit the application */
    QObject::connect(&ws, SIGNAL(Stopped()), &qca, SLOT(quit()));

    /***
     * Set up Web Services
     */
    QSharedPointer<Dissent::Messaging::SignalSink> signal_sink(new Dissent::Messaging::SignalSink());
    nodes[0]->sink = signal_sink;

    QSharedPointer<GetMessagesService> get_messages_sp(new GetMessagesService());
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_messages_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));

    QSharedPointer<GetNextMessageService> get_next_message_sp(new GetNextMessageService());  
    QObject::connect(signal_sink.data(), SIGNAL(IncomingData(const QByteArray&)),
        get_next_message_sp.data(), SLOT(HandleIncomingMessage(const QByteArray&)));

    QSharedPointer<RoundIdService> round_id_sp(new RoundIdService(nodes[0]->session));
    QSharedPointer<SessionIdService> session_id_sp(new SessionIdService(nodes[0]->session));
    QSharedPointer<SendMessageService> send_message_sp(new SendMessageService(nodes[0]->session));

    ws.AddRoute(HttpRequest::METHOD_HTTP_GET, "/round/id", round_id_sp);
    ws.AddRoute(HttpRequest::METHOD_HTTP_POST, "/session/send", send_message_sp);
    ws.AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/id", session_id_sp);
    ws.AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages/all", get_messages_sp);
    ws.AddRoute(HttpRequest::METHOD_HTTP_GET, "/session/messages/next", get_next_message_sp);

    ws.Start();
  } else {
    nodes[0]->sink = QSharedPointer<ISink>(new DummySink());
  }

  return QCoreApplication::exec();
}

