#include <QObject>

class QHttpRequest;
class QHttpResponse;

class BodyData : public QObject
{
    Q_OBJECT
public:
    BodyData();

private slots:
    void handle(QHttpRequest *req, QHttpResponse *resp);
};

class Responder : public QObject
{
    Q_OBJECT
public:
    Responder(QHttpRequest *req, QHttpResponse *resp);
    ~Responder();
signals:
    void done();
private slots:
    void accumulate(const QByteArray&);
    void reply();
private:
    QHttpRequest *m_req;
    QHttpResponse *m_resp;
};
