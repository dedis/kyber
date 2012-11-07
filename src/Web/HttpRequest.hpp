#ifndef DISSENT_WEB_HTTP_REQUEST_H_GUARD
#define DISSENT_WEB_HTTP_REQUEST_H_GUARD

#include <QHash>
#include <QObject>
#include <QString>
#include <QUrl>

extern "C" {
#include "http_parser.h"
}

namespace Dissent {
namespace Web {

  /** 
   * Represents an HTTP request (method, URL, headers, body)
   * and contains the parsing logic for HTTP requests
   */

  class HttpRequest { 
    public:
      /* We only support these methods */
      enum RequestMethod {
        METHOD_HTTP_DELETE,
        METHOD_HTTP_GET,
        METHOD_HTTP_HEAD,
        METHOD_HTTP_POST,
        METHOD_HTTP_PUT
      };

      /**
       * Constructor
       */
      explicit HttpRequest();
      
      virtual ~HttpRequest();

      /**
       * Parse request from a QByteArray. Returns
       * true if parsed ok and false otherwise.
       * @param the byte array
       */
      bool ParseRequest(QByteArray &raw_data);

      /**
       * Print a summary of the HTTP request 
       * to the debug output
       */
      void PrintDebug() const;

      /**
       * Get the HTTP request method
       */
      RequestMethod GetMethod() const;

      /**
       * Get the URL requested
       */
      QUrl GetUrl() const;

      /**
       * Get the URL path requested
       * if the request is for
       *   https://long.domain.name.com/stuff/morestuff.html?123-123-123
       * then the path is:
       *   /stuff/morestuff.html
       */
      QString GetPath() const;

      QHash<QString, QString> GetHeader() const
      {
        return _header_map;
      }

      QString GetHeaderValue(const QString &key) const
      {
        return _header_map.value(key);
      }

      /**
       * Get the request body 
       */
      QString GetBody() const;

      /* Callbacks */
      int OnMessageBegin(struct http_parser* _parser);
      int OnHeaderField(struct http_parser* _parser,
          const char* at, size_t length);
      int OnHeaderValue(struct http_parser* _parser,
          const char* at, size_t length);
      int OnUrl(struct http_parser* _parser,
          const char* at, size_t length);
      int OnHeadersComplete(struct http_parser*  _parser);
      int OnBody(struct http_parser* _parser,
          const char* at, size_t length);
      int OnMessageComplete(struct http_parser* _parser);

    private:
      HttpRequest &operator=(const HttpRequest &);
      void ParseUrl();

      bool _parsed, _success;
      QHash<QString, QString> _header_map;
      QString _last_header;
      QUrl _url;
      QString  _path;
      QString _body;
      RequestMethod _method;
      struct http_parser_settings _parser_settings;
      struct http_parser _parser;
  };
}
}

#endif
