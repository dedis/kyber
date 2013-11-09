#ifndef DISSENT_UTILS_CALLBACK_H_GUARD
#define DISSENT_UTILS_CALLBACK_H_GUARD

#include <QSharedPointer>

namespace Dissent {
namespace Utils {
  /**
   * Common Callback so it can be stored in a template datastore
   */
  template<typename T> class BaseCallback {
    public:
      /**
       * Invoke the callback
       */
      virtual void Invoke(T) = 0;

      /**
       * Destructor
       */
      virtual ~BaseCallback() {}
  };

  /**
   * A common class for holding Timer callbacks with only a single state variable
   */
  template<typename S, typename T> class Callback : public BaseCallback<T> {
    public:
      /**
       * Typedef for Method callbacks
       */
      typedef void (S::*Method)(T);

      /**
       * Constructs a new TimerMethod
       * @param object the callback object
       * @param method the method to callback
       * @param val the state to callback
       */
      explicit Callback(S *object, Method method) :
        m_object(object),
        m_method(method)
      {
      }

      /**
       * Destructor
       */
      virtual ~Callback() {}

      inline virtual void Invoke(T val)
      {
        (m_object->*m_method)(val);
      }

    private:
      S *m_object;
      Method m_method;
  };
}
}

#endif
