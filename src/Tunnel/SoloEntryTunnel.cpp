#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTcpSocket>
#include <QUrl>
#include <QxtCommandOptions>

#include "EntryTunnel.hpp"
#include "Utils/Logging.hpp"

class SoloEntryTunnel : public QObject {
  Q_OBJECT
  public:
    SoloEntryTunnel(const QUrl &tunnel, const QUrl &forwarder);

  private slots:
    /**
     * Successfully connected, let's begin!
     */
    void Connected();

    /**
     * Disconnect occurred on our socket with the remote network.
     * This is unexpected...
     */
    void Disconnected();

    /**
     * Error occurred on our socket with the remote network
     */
    void Error();

    /**
     * Alternatively ToTunnel, data from the network to the tunnel
     */
    void FromSocket();

    /**
     * Alternatively ToSocket, data from the tunnel to the network
     */
    void FromTunnel(const QByteArray &data);

  private:
    QTcpSocket m_client;
    Dissent::Tunnel::EntryTunnel m_entry;
};

int PrintError(const QString &app, const QString &error,
    const QxtCommandOptions &options);

int main(int argc, char **argv)
{
  QCoreApplication aca(argc, argv);
  QStringList args = QCoreApplication::arguments();

  QxtCommandOptions options;
  options.add("tunnel", "Url for tunnel: tcp://ip:port",
      QxtCommandOptions::ValueRequired);
  options.add("forwarder", "Url for forwarder: tcp://ip:port",
      QxtCommandOptions::ValueRequired);
  options.add("debug", "Enabling debugging output",
      QxtCommandOptions::NoValue);
  options.parse(args);

  if(!options.count("debug")) {
    Dissent::Utils::Logging::Disable();
  }

  if(!options.count("tunnel")) {
    return PrintError(QString(argv[0]), "Missing tunnel option", options);
  }

  QUrl tunnel(options.value("tunnel").toString());
  if(!tunnel.isValid()) {
    return PrintError(QString(argv[0]), "Invalid tunnel url", options);
  }

  if(!options.count("forwarder")) {
    return PrintError(QString(argv[0]), "Missing forwarder url", options);
  }

  QUrl forwarder(options.value("forwarder").toString());
  if(!forwarder.isValid()) {
    return PrintError(QString(argv[0]), "Invalid forwarder url", options);
  }

  SoloEntryTunnel set(tunnel, forwarder);
  return QCoreApplication::exec();
}

int PrintError(const QString &app, const QString &error,
    const QxtCommandOptions &options)
{
  QTextStream qtout(stdout, QIODevice::WriteOnly);
  qtout << "usage: " << app << " [options] [settings.conf]\n\n";
  qtout << "options:\n";
  qtout << options.getUsage() << "\n";
  qtout << "error: " << error << "\n\n";
  return -1;
}

SoloEntryTunnel::SoloEntryTunnel(const QUrl &tunnel, const QUrl &forwarder) :
      m_client(0),
      m_entry(tunnel)
{
  connect(&m_client, SIGNAL(connected()),
      this, SLOT(Connected()));
  connect(&m_client, SIGNAL(disconnected()),
      this, SLOT(Disconnected()));
  connect(&m_client, SIGNAL(error(QAbstractSocket::SocketError)),
      this, SLOT(Error()));
  connect(&m_client, SIGNAL(readyRead()),
      this, SLOT(FromSocket()));

  m_client.connectToHost(forwarder.host(), forwarder.port(19080));
}

/**
 * Successfully connected, let's begin!
 */
void SoloEntryTunnel::Connected()
{
  qDebug() << "Connected with remote host, ready to begin";
  connect(&m_entry, SIGNAL(OutgoingDataSignal(const QByteArray &)),
      this, SLOT(FromTunnel(const QByteArray &)));
  m_entry.Start();
}

/**
 * Disconnect occurred on our socket with the remote network.
 * This is unexpected...
 */
void SoloEntryTunnel::Disconnected()
{
  qCritical() << "Remote socket disconnected, service terminating";
  QCoreApplication::exit(-1);
}

/**
 * Error occurred on our socket with the remote network
 */
void SoloEntryTunnel::Error()
{
  qCritical() << "Socket error:" << m_client.errorString() << "... terminating";
  QCoreApplication::exit(-1);
}

/**
 * Alternatively ToTunnel, data from the network to the tunnel
 */
void SoloEntryTunnel::FromSocket()
{
  QByteArray data = m_client.peek(m_client.bytesAvailable());
  QByteArray current = data;
  int read = 0;

  while(true) {
    Dissent::Tunnel::TunnelPacket packet(current);
    if(!packet.IsValid()) {
      break;
    }
    m_entry.IncomingData(packet);
    read += packet.GetLength();
    current = QByteArray::fromRawData(data.constData() + read, data.size() - read);
    qDebug() << "Found a valid packet!";
  }
  m_client.read(read);
}

/**
 * Alternatively ToSocket, data from the tunnel to the network
 */
void SoloEntryTunnel::FromTunnel(const QByteArray &data)
{
  Q_ASSERT(m_client.write(data) == data.size());
}

#include "SoloEntryTunnel.moc"
