#ifndef DISSENT_MESSAGING_GET_DATA_CALLBACK_H_GUARD
#define DISSENT_MESSAGING_GET_DATA_CALLBACK_H_GUARD

#include <QByteArray>
#include <QPair>

namespace Dissent {
namespace Messaging {
  /**
   * A fancy callback holder so Round doesn't need to know about Session
   */
  class GetDataCallback {
    public:
      /**
       * Requests data upto the max amount of bytes specified, returns an array
       * containing the data and a bool if there is more data pending.
       * @param max maximum amount of bytes to return.
       */
      virtual QPair<QByteArray, bool> operator()(int max) = 0;

      /**
       * Destructor
       */
      virtual ~GetDataCallback() {}
  };

  class EmptyGetDataCallback : public GetDataCallback {
    public:
      static GetDataCallback &GetInstance()
      {
        static EmptyGetDataCallback callback;
        return callback;
      }

      virtual QPair<QByteArray, bool> operator()(int)
      {
        static QPair<QByteArray, bool> pair(QByteArray(), false);
        return pair;
      }

      /**
       * Destructor
       */
      ~EmptyGetDataCallback() {}
  };

  template<typename T> class GetDataMethod : public GetDataCallback {
    public:
      /**
       * T method signature
       */
      typedef QPair<QByteArray, bool> (T::*Method)(int max);

      GetDataMethod(T *object, Method method) :
        _object(object), _method(method)
      {
      }

      /**
       * Destructor
       */
      ~GetDataMethod() {}

      inline virtual QPair<QByteArray, bool> operator()(int max)
      {
        return (_object->*_method)(max);
      }

    private:
      T *_object;
      Method _method;
  };
}
}

#endif
