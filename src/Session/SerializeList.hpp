#ifndef DISSENT_SESSION_SERIALIZE_H_GUARD
#define DISSENT_SESSION_SERIALIZE_H_GUARD

#include <QByteArray>
#include <QDataStream>
#include <QIODevice>
#include <QList>

namespace Dissent {
namespace Session {
  template<typename T>
    QByteArray SerializeList(const QList<QSharedPointer<T> > &list)
  {
    QByteArray data;
    QDataStream stream(&data, QIODevice::WriteOnly);

    stream << list.count();
    foreach(const QSharedPointer<T> &element, list) {
      stream << element->GetPacket();
    }

    return data;
  }

  template<typename T>
    QList<QSharedPointer<T> > DeserializeList(const QByteArray &data)
  {
    QDataStream stream(data);

    int count;
    stream >> count;

    QList<QSharedPointer<T> > list;
    if(count < 0) {
      return list;
    }

    while(count-- && stream.status() == QDataStream::Ok) {
      QByteArray entry;
      stream >> entry;
      list.append(QSharedPointer<T>(new T(entry)));
    }

    return list;
  }
}
}


#endif
