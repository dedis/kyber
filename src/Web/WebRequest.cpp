
#include "WebRequest.hpp"

namespace Dissent {
namespace Web {

  WebRequest::WebRequest(QTcpSocket* socket) :
    _socket(socket),
    _request(new HttpRequest()),
    _status(HttpResponse::STATUS_INTERNAL_SERVER_ERROR),
    _length(-1),
    _processing(false)
  {
    connect(_socket, SIGNAL(readyRead()), this, SLOT(ReadSocket()));
    connect(_socket, SIGNAL(disconnected()), this, SLOT(Disconnected()));
    connect(_socket, SIGNAL(error(QAbstractSocket::SocketError)),
        SLOT(HandleError(QAbstractSocket::SocketError)));
    connect(_socket, SIGNAL(bytesWritten(qint64)), this, SLOT(WriteCheck()));
  }

  WebRequest::~WebRequest() 
  {
    if(_socket) {
      _socket->flush();
      _socket->close();
      _socket->deleteLater();
    }
  }

  bool WebRequest::WriteFinished() const
  {
    return _processing && _socket->bytesToWrite() == 0;
  }

  void WebRequest::WriteCheck()
  {
    qDebug() << WriteFinished();
    if(!WriteFinished()) {
      return;
    }
    emit ResponseFinished();
  }

  void WebRequest::ReadSocket()
  {
    if(_processing) {
      return;
    }

    QByteArray data = _socket->readAll();
    if(_length > 0) {
      _incoming.append(data);
      if(_incoming.size() < _length) {
        return;
      }
      data = _incoming;
      _request = QSharedPointer<HttpRequest>(new HttpRequest());
    }

    qDebug() << "Reading from WebService socket";
    if(_request->ParseRequest(data)) {
      _request->PrintDebug();
      EmitFinished(true);
    } else if(_length == -1) {
      _length = _request->GetHeaderValue("Content-Length").toInt();
      if(_length <= 0) {
        qDebug() << "Invalid content-length";
        EmitFinished(false);
      } else {
        qDebug() << "Need more bytes...";
        _incoming = data;
      }
    } else {
      qDebug() << "Wonky request";
      EmitFinished(false);
    }
  }

  void WebRequest::EmitFinished(bool status)
  {
    _processing = true;
    emit Finished(status);
  }

  void WebRequest::Disconnected()
  {
    EmitFinished(false);
  }

  void WebRequest::HandleError(QAbstractSocket::SocketError)
  {
    qWarning() << "Socket error: " << _socket->errorString();
    EmitFinished(false);
  }

}
}
