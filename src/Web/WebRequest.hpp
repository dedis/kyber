#ifndef DISSENT_WEB_WEB_REQUEST_H_GUARD
#define DISSENT_WEB_WEB_REQUEST_H_GUARD

#include <QObject>
#include <QSharedPointer>
#include <QTcpSocket>
#include <QVariant>

#include "HttpRequest.hpp"
#include "HttpResponse.hpp"

namespace Dissent {
namespace Web {

  /**
   * WebRequest holds all of the data that
   * a web service needs to process a request
   * and return a response data object
   */
  class WebRequest : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       */
      explicit WebRequest(QTcpSocket* socket);
      
      virtual ~WebRequest();

      inline QTcpSocket* GetSocket() { Q_ASSERT(_socket); return _socket; }

      inline const HttpRequest &GetRequest() const { return *_request; }

      inline QVariant &GetOutputData() { return _output_data; }

      inline HttpResponse::StatusCode GetStatus() const { return _status; }

      inline void SetStatus(HttpResponse::StatusCode status) { _status = status; }

      bool WriteFinished() const;

    signals:
      void Finished(bool success);
      void ResponseFinished();

    private:
      void EmitFinished(bool status);
      
      QByteArray _current_data;
      QTcpSocket* _socket;
      QSharedPointer<HttpRequest> _request;

      QVariant _output_data;
      HttpResponse::StatusCode _status;
      QByteArray _incoming;
      int _length;
      bool _processing;

    private slots:
      void WriteCheck();
      void ReadSocket();
      void Disconnected();
      void HandleError(QAbstractSocket::SocketError);
  };
}
}

#endif
