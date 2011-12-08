#ifndef DISSENT_WEB_HTTP_RESPONSE_H_GUARD
#define DISSENT_WEB_HTTP_RESPONSE_H_GUARD

#include <QHash>
#include <QObject>
#include <QString>
#include <QTextStream>
#include <QTcpSocket>

namespace Dissent {
namespace Web {
  
  /**
   * Encapsulates an HTTP response (status, headers, body)
   * and contains methods for writing the response out
   * to a socket 
   */

  class HttpResponse : public QObject {
    Q_OBJECT

    public:

    enum StatusCode {
      STATUS_OK = 200,
      STATUS_MOVED_PERMANENTLY = 301,
      STATUS_FOUND = 302,
      STATUS_BAD_REQUEST = 400,
      STATUS_FORBIDDEN = 403,
      STATUS_NOT_FOUND = 404,
      STATUS_INTERNAL_SERVER_ERROR = 500,
      STATUS_NOT_IMPLEMENTED = 501
    };

      /**
       * Constructor
       */
      HttpResponse();
      
      ~HttpResponse();

      /**
       * Set the HTTP status code to use
       * as a response
       * @param the status code
       */
      void SetStatusCode(StatusCode status);

      /**
       * Add a new header to the HTTP response
       * @param the name of the header
       * @param the header's value
       */
      void AddHeader(QString key, QString value);

      /**
       * Return true if the given header is already
       * set
       * @param header to check
       */
      bool HasHeader(const QString& key);

      /**
       * Write the response to the output stream
       * @param the output stream
       */
      void WriteToStream(QTextStream& ostream);

      /**
       * Write the response to an open TCP socket
       * @param the open socket
       */
      void WriteToSocket(QTcpSocket *socket);

      /** 
       * Get a string describing the status code
       * @param the status code
       */
      QString TextForStatus(StatusCode status);

    public:
      QString GetBody();

    public:
      QTextStream body;

    private:
      QString _http_version, _eol, _body;
      StatusCode _status_code;
      QHash<StatusCode, QString> _status_map;
      QHash<QString, QString> _header_map;
  };
}
}

#endif
