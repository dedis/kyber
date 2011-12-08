
#include <QDebug>

#include "HttpResponse.hpp"

namespace Dissent {
namespace Web {

  HttpResponse::HttpResponse() :
    body(&_body, QFlags<QIODevice::OpenModeFlag>(QIODevice::WriteOnly)),
    _http_version("HTTP/1.1"),
    _eol("\r\n"),
    _status_code(STATUS_OK)
  {
    _status_map.insert(STATUS_OK, "OK");
    _status_map.insert(STATUS_MOVED_PERMANENTLY, 
        "Moved Permanently");
    _status_map.insert(STATUS_FOUND, "Found");
    _status_map.insert(STATUS_BAD_REQUEST, "Bad Request");
    _status_map.insert(STATUS_FORBIDDEN, "Forbidden");
    _status_map.insert(STATUS_NOT_FOUND, "Not Found");
    _status_map.insert(STATUS_INTERNAL_SERVER_ERROR, 
        "Internal Server Error");
    _status_map.insert(STATUS_NOT_IMPLEMENTED, 
        "Not Implemented");
  }
  
  HttpResponse::~HttpResponse() 
  {
    _status_map.clear();
  }

  void HttpResponse::SetStatusCode(StatusCode status) 
  {
    _status_code = status; 
  }

  void HttpResponse::AddHeader(QString key, QString value)
  {
    _header_map.insert(key, value); 
  }

  bool HttpResponse::HasHeader(const QString& key)
  {
    return _header_map.contains(key);
  }

  QString HttpResponse::GetBody()
  {
    if(!_body.isEmpty()) {
      return _body;
    } 
    
    QString def = "<html><h1>";
    def += _status_map[_status_code];
    def += "</h1></html>";
    return def;
  }

  void HttpResponse::WriteToStream(QTextStream& ostream)
  {
    QString resp_body = GetBody();
    AddHeader("Content-Length", QString("%1").arg(resp_body.length()));

    qDebug() << "Starting to write";
    ostream << _http_version << " ";
    ostream << _status_code << " " << _status_map[_status_code];
    ostream << _eol;
    
    QHash<QString, QString>::iterator i;
    for(i=_header_map.begin(); i!=_header_map.end(); ++i) {
      ostream << i.key() << ": " << i.value() << _eol;
    }
    ostream << _eol;
    ostream << resp_body;
  }

  void HttpResponse::WriteToSocket(QTcpSocket *socket)
  {
    if(!socket->isWritable()) return;
    QTextStream os(socket);
    os.setAutoDetectUnicode(true);
    WriteToStream(os); 
    os.flush();
  }

  QString HttpResponse::TextForStatus(StatusCode status)
  {
    if(_status_map.contains(status)) {
      return _status_map[status];
    } else {
      return QString("Unknown");
    }
  }
}
}

