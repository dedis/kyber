#include <QByteArray>
#include <QObject>
#include <QString>
#include <QTcpServer>
#include <QTcpSocket>
#include <QUrl>
#include <QxtCommandOptions>

#include "ExitTunnel.hpp"
#include "Utils/Logging.hpp"

using Dissent::Tunnel::TunnelPacket;
using Dissent::Tunnel::ExitTunnel;

/**
 * A simple class for moving data from a socket into the ExitTunnel.
 * This supports for now only a single client,
 * but it can be resumed after a disconnect.
 */
class SoloExitTunnel : public QObject {
  Q_OBJECT

  public:
    SoloExitTunnel(const QUrl &tunnel, const QUrl &forwarder);

  private slots:
    /**
     * Someone is calling
     */
    void IncomingConnection();

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
    void FromTunnel(const TunnelPacket &packet);

  private:
    QTcpServer m_server;
    QSharedPointer<QTcpSocket> m_socket;
    ExitTunnel m_exit;
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

  QUrl tunnel = QUrl();
  if(options.count("tunnel")) {
    tunnel = QUrl(options.value("tunnel").toString());
    if(!tunnel.isValid()) {
      return PrintError(QString(argv[0]), "Invalid tunnel url", options);
    }
  }

  if(!options.count("forwarder")) {
    return PrintError(QString(argv[0]), "Missing forwarder url", options);
  }

  QUrl forwarder(options.value("forwarder").toString());
  if(!forwarder.isValid()) {
    return PrintError(QString(argv[0]), "Invalid forwarder url", options);
  }

  SoloExitTunnel set(tunnel, forwarder);
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

SoloExitTunnel::SoloExitTunnel(const QUrl &tunnel, const QUrl &forwarder) :
  m_exit(tunnel)
{
  connect(&m_server, SIGNAL(newConnection()), this, SLOT(IncomingConnection()));
  Q_ASSERT(m_server.listen(QHostAddress(forwarder.host()), forwarder.port(19080)));
  m_exit.Start();
}

void SoloExitTunnel::IncomingConnection()
{
  while(m_server.hasPendingConnections()) {
    QTcpSocket *socket = m_server.nextPendingConnection();
    if(m_socket) {
      connect(socket, SIGNAL(disconnected()), socket, SLOT(deleteLater()));
      socket->disconnectFromHost();
    } else {
      m_socket = QSharedPointer<QTcpSocket>(socket, &QObject::deleteLater);
      connect(socket, SIGNAL(disconnected()), this, SLOT(Disconnected()));
      connect(socket, SIGNAL(error(QAbstractSocket::SocketError)),
          this, SLOT(Error()));
      connect(socket, SIGNAL(readyRead()), this, SLOT(FromSocket()));
      connect(&m_exit, SIGNAL(OutgoingDataSignal(const TunnelPacket &)),
          this, SLOT(FromTunnel(const TunnelPacket &)));
    }
  }
}

void SoloExitTunnel::Disconnected()
{
  qDebug() << "Disconnected, a new connection may form";
  disconnect(&m_exit, SIGNAL(OutgoingDataSignal(const TunnelPacket &)),
      this, SLOT(FromTunnel(const TunnelPacket &)));
  m_socket.clear();
}

void SoloExitTunnel::Error()
{
  qDebug() << "Socket error:" << m_socket->errorString();
}

void SoloExitTunnel::FromSocket()
{
  qDebug() << "???";
  QByteArray data = m_socket->peek(m_socket->bytesAvailable());
  QByteArray current = data;
  int read = 0;

  while(true) {
    Dissent::Tunnel::TunnelPacket packet(current);
    if(!packet.IsValid()) {
      break;
    }
    m_exit.IncomingData(packet);
    read += packet.GetLength();
    current = QByteArray::fromRawData(data.constData() + read, data.size() - read);
    qDebug() << "Found a valid packet!";
  }
  m_socket->read(read);
}

void SoloExitTunnel::FromTunnel(const Dissent::Tunnel::TunnelPacket &packet)
{
  qDebug() << "HERE?";
  Q_ASSERT(m_socket->write(packet.GetPacket(), packet.GetPacket().size()));
}

#include "SoloExitTunnel.moc"
