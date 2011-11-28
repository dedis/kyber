#ifndef DISSENT_TIMER_CALLBACK_H_GUARD
#define DISSENT_TIMER_CALLBACK_H_GUARD

namespace Dissent {
namespace Utils {
  /**
   * Common Callback so it can be stored in a template datastore
   */
  class TimerCallback {
    public:
      /**
       * Invoke the callback
       */
      virtual void Invoke() = 0;

      /**
       * Destructor
       */
      virtual ~TimerCallback() {}
  };

  /**
   * A common class for holding Timer callbacks with only a single state variable
   */
  template<typename S, typename T> class TimerMethod : public TimerCallback {
    public:
      /**
       * Typedef for Method callbacks
       */
      typedef void (S::*Method)(const T &val);

      /**
       * Constructs a new TimerMethod
       * @param object the callback object
       * @param method the method to callback
       * @param val the state to callback
       */
      TimerMethod(S *object, Method method, T val) :
        _object(object), _method(method), _val(val)
      {
      }

      /**
       * Destructor
       */
      virtual ~TimerMethod() {}

      inline virtual void Invoke()
      {
        (_object->*_method)(_val);
      }

    private:
      S *_object;
      Method _method;
      T _val;
  };
}
}

#endif
