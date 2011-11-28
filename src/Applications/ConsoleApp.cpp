#include <QCoreApplication>
#include <QDebug>

#include "../Dissent.hpp"

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

  QList<QSharedPointer<Node> > nodes;

  Id local_id;
  if(!settings.LocalId.isEmpty()) {
    local_id = Id(settings.LocalId);
  }

  QSharedPointer<AsymmetricKey> key;
  QSharedPointer<DiffieHellman> dh;

  if(settings.DemoMode) {
    QByteArray id = nodes[0]->bg.GetId().GetByteArray();
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
      QByteArray id = nodes[idx]->bg.GetId().GetByteArray();
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

  if(settings.Console) {
    QSharedPointer<CommandLine> cl(new CommandLine(nodes));
    QObject::connect(nodes[0].data(), SIGNAL(Ready()), cl.data(), SLOT(Ready()));
    nodes[0]->sink = cl;
    cl->Start();
    QObject::connect(&qca, SIGNAL(aboutToQuit()), cl.data(), SLOT(Stop()));
  } else {
    nodes[0]->sink = QSharedPointer<ISink>(new DummySink());
  }

  return QCoreApplication::exec();
}
