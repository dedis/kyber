#include "WebService.hpp"

namespace Dissent {
namespace Web {
  WebService::~WebService()
  {
  }

  QByteArray WebService::BuildJsonResponse(const QVariant &data, bool &success)
  {
    QByteArray bresponse = QtJson::Json::serialize(data, success);
    if(!success) {
      return QByteArray();
    }
    return bresponse;
  }

  void WebService::SendNotFound(QHttpResponse *response)
  {
    QByteArray msg = "Error: Not Found";
    response->setHeader("content-length", QString::number(msg.size()));
    response->writeHead(QHttpResponse::STATUS_NOT_FOUND);
    response->write(msg);
    response->end();
  }

  void WebService::SendResponse(QHttpResponse *response, const QByteArray &data)
  {
    response->setHeader("content-length", QString::number(data.size()));
    response->writeHead(QHttpResponse::STATUS_OK);
    response->write(data);
    response->end();
  }

  void WebService::SendJsonResponse(QHttpResponse *response, const QVariant &data)
  {
    bool success;
    QByteArray output = QtJson::Json::serialize(data, success);
    if(!success) {
      response->setHeader("content-length", QString::number(0));
      response->writeHead(QHttpResponse::STATUS_INTERNAL_SERVER_ERROR);
    } else {
      response->setHeader("content-length", QString::number(output.size()));
      response->writeHead(QHttpResponse::STATUS_OK);
      response->write(output);
    }
    response->end();
  }
}
}
