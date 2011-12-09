#ifndef DISSENT_UTILS_SIGNAL_COUNTER_H_GUARD
#define DISSENT_UTILS_SIGNAL_COUNTER_H_GUARD

#include <QObject>

namespace Dissent {
namespace Utils {
  /**
   * Counts the amount of signals the slot has received.  This was created
   * because it is a pain to create QObjects / slots in cpp files.
   */
  class SignalCounter : public QObject {
    Q_OBJECT

    public:
      /**
       * Constructor
       */
      explicit SignalCounter(int max = -1) : _max(max), _count(0) { }

      /**
       * Destructor
       */
      virtual ~SignalCounter() {}

      /**
       * Returns the amount of signals that have been registered thus far
       */
      inline int GetCount() { return _count; }

      /**
       * Resets the count of signals to 0
       */
      inline void Reset() { _count = 0; }

      /**
       * Returns the expected count
       */
      inline int Max() { return _max; }

    public slots:
      /**
       * Register all signals to this slot
       */
      void Counter() { ++_count; }

    private:
      int _max;
      int _count;
  };
}
}

#endif
