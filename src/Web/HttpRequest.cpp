
#include <QByteArray>
#include <QDebug>

#include "HttpRequest.hpp"

#define CALLBACK_WRAPPER(NAME) \
  int wrapper_ ## NAME (struct http_parser* _parser) \
  { \
    HttpRequest* request = (HttpRequest*)_parser->data; \
    if(!request) { \
      qFatal("Cannot cast HttpRequest object"); \
    } \
    return request-> NAME (_parser); \
  }\


#define CALLBACK_DATA_WRAPPER(NAME) \
  int wrapper_ ## NAME (struct http_parser* _parser, \
      const char* at, size_t length) \
  { \
    HttpRequest* request = (HttpRequest*)_parser->data; \
    if(!request) { \
      qFatal("Cannot cast HttpRequest object"); \
    } \
    return request-> NAME (_parser, at, length); \
  }\


namespace Dissent {
namespace Web {

  /* 
   * Oh no! Macros! Why like this?
   * 
   * The HTTP parser uses C-style callbacks
   * to communicate back to the caller.
   * The true callbacks are inside of the
   * HttpRequest object -- we just use these
   * non-objectified wrapper functions to 
   * so that we can pass them to the parser.
   * The macros just produce the boilerplate
   * wrapper code.
   */
  CALLBACK_WRAPPER(OnMessageBegin);
  CALLBACK_DATA_WRAPPER(OnHeaderField);
  CALLBACK_DATA_WRAPPER(OnHeaderValue);
  CALLBACK_DATA_WRAPPER(OnUrl);
  CALLBACK_WRAPPER(OnHeadersComplete);
  CALLBACK_DATA_WRAPPER(OnBody);
  CALLBACK_WRAPPER(OnMessageComplete);
  
  HttpRequest::HttpRequest() :
    _parsed(false),
    _last_header(QString())
  {
    _parser.data = (void*)this;
    http_parser_init(&_parser, HTTP_REQUEST);
   
    _parser_settings.on_message_begin = &wrapper_OnMessageBegin;
    _parser_settings.on_header_field = &wrapper_OnHeaderField;
    _parser_settings.on_url = &wrapper_OnUrl;
    _parser_settings.on_header_value = &wrapper_OnHeaderValue;
    _parser_settings.on_headers_complete = &wrapper_OnHeadersComplete;
    _parser_settings.on_body = &wrapper_OnBody;
    _parser_settings.on_message_complete = &wrapper_OnMessageComplete;
  }
      
  HttpRequest::~HttpRequest() {}

  void HttpRequest::PrintDebug()
  {
    qDebug() << "=======HTTP Request======";
    if(_parsed) {
      qDebug() << "U |" << _url;
      qDebug() << "M |" << _method;
      QHash<QString,QString>::const_iterator i;
      for(i = _header_map.constBegin(); i != _header_map.constEnd(); ++i) {
        qDebug() << "H |" << i.key() << ":" << i.value(); 
      }
      qDebug() << "Body---------------------";
      qDebug() << _body; 
    } else {
      qDebug() << "Not parsed yet";
    }
    qDebug() << "=========================";
  }

  HttpRequest::RequestMethod HttpRequest::GetMethod()
  {
    if(!_parsed) {
      qFatal("Cannot return request method on unparsed request");
    }

    return _method;
  }

  QUrl HttpRequest::GetUrl()
  {
    if(!_parsed) {
      qFatal("Cannot return request URL on unparsed request");
    }

    return _url;
  }


  QString HttpRequest::GetBody()
  {
    if(!_parsed) {
      qFatal("Cannot return body on unparsed request");
    }

    return _body;
  }

  QString HttpRequest::GetPath()
  {
    if(!_parsed) {
      qFatal("Cannot return URL path on unparsed request");
    }

    return _path;
  }

  /*
   * CALLBACKS ******************
   */

  int HttpRequest::OnMessageBegin(struct http_parser* /* _parser */)
  {
    qDebug() << "OnMessageBegin()";
    return 0;
  }

  int HttpRequest::OnHeaderField(struct http_parser* /*_parser */,
      const char* at, size_t length)
  {

    _last_header = QString::fromAscii(at, length);
    return 0;
  }

  int HttpRequest::OnHeaderValue(struct http_parser* /*_parser*/,
      const char* at, size_t length)
  {
    if(!_last_header.length()) {
      qWarning() << "Got header value without header name";
      return 1;
    }

    if(_last_header == "Host") {
      _url.setAuthority(QByteArray(at, length));
      qDebug() << "Setting host" << _url;
    }

    QString value = QString::fromAscii(at, length);
    _header_map.insert(_last_header, value);
    _last_header = QString();

    return 0;
  }
  
  int HttpRequest::OnUrl(struct http_parser* /*_parser*/,
      const char* at, size_t length)
  {
    QByteArray url_bytes = QByteArray(at, length);
    _url.setEncodedPath(url_bytes);
    
    qDebug() << "URL:" << _url;
    return 0;
  }

  int HttpRequest::OnHeadersComplete(struct http_parser* _parser)
  {
    unsigned char method_code = _parser->method;
    switch(method_code) {
      case HTTP_DELETE:
        _method = METHOD_HTTP_DELETE;
        break;
      case HTTP_GET:
        _method = METHOD_HTTP_GET;
        break;
      case HTTP_HEAD:
        _method = METHOD_HTTP_HEAD;
        break;
      case HTTP_POST:
        _method = METHOD_HTTP_POST;
        break;
      case HTTP_PUT:
        _method = METHOD_HTTP_PUT;
        break;
      default:
        /* Return non-zero, indicating an error */
        return 2;
        break;
    }

    qDebug() << "OnHeadersComplete() Method:" << (int)_method;
    return 0;
  }

  int HttpRequest::OnBody(struct http_parser* /*_parser*/,
      const char* at, size_t length)
  {
    _body = QString::fromAscii(at, length);
    qDebug() << "Body:" << _url;
    return 0;
  }

  int HttpRequest::OnMessageComplete(struct http_parser* /* _parser */)
  {
    qDebug() << "OnMessageComplete()";
    return 0;
  }

  bool HttpRequest::ParseRequest(QByteArray &raw_data) {
    qDebug("Starting to parse");
    int len = raw_data.length();
    int bytes_proc = http_parser_execute(&_parser, 
        &_parser_settings, raw_data.constData(), len);

    if(bytes_proc != raw_data.length()) {
      qWarning("Parsing error!");
      return false;
    }

    ParseUrl();
  
    _parsed = true;
    return true;
  }

  void HttpRequest::ParseUrl()
  {
    QString ustr = _url.toString(QUrl::RemoveAuthority| 
        QUrl::RemoveQuery|QUrl::RemoveScheme|QUrl::RemoveFragment);

    /* Ensure that the query string has a positive length */
    if(!ustr.length()) {
      _path = "/";
    }
    
    int ind = ustr.indexOf("?", 1);
    if(ind > 0) {
      ustr = ustr.left(ind);
    }

    _path = ustr;
  }
}
}

