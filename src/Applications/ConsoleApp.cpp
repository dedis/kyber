#include <QCoreApplication>
#include <QDebug>

#include "../Dissent.hpp"

using namespace Dissent::Applications;

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

  QList<QSharedPointer<Node> > nodes;

  nodes.append(QSharedPointer<Node>(new Node(local, remote, settings.GroupSize, settings.SessionType)));
  if(settings.DemoMode) {
    AsymmetricKey *key = CppPrivateKey::GenerateKey(nodes[0]->bg.GetId().GetByteArray());
    nodes[0]->key = QSharedPointer<AsymmetricKey>(key);
  }

  for(int idx = 1; idx < settings.LocalNodeCount; idx++) {
    local[0] = AddressFactory::GetInstance().CreateAny(local[0].GetType());
    nodes.append(QSharedPointer<Node>(new Node(local, remote, settings.GroupSize, settings.SessionType)));
    if(settings.DemoMode) {
      AsymmetricKey *key = CppPrivateKey::GenerateKey(nodes[idx]->bg.GetId().GetByteArray());
      nodes[idx]->key = QSharedPointer<AsymmetricKey>(key);
    }
    nodes[idx]->sink = QSharedPointer<ISink>(new DummySink());
  }

  foreach(QSharedPointer<Node> node, nodes) {
    node->bg.Start();
  }

  QSharedPointer<CommandLine> cl(new CommandLine(nodes));
  QObject::connect(nodes[0].data(), SIGNAL(Ready(Node *)), cl.data(), SLOT(Ready()));
  nodes[0]->sink = cl;

  cl->Start();
  QCoreApplication::exec();
  cl->Stop();

  foreach(QSharedPointer<Node> node, nodes) {
    node->bg.Stop();
  }

  return 0;
}
