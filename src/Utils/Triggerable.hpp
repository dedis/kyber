#ifndef DISSENT_UTILS_TRIGGERABLE_H_GUARD
#define DISSENT_UTILS_TRIGGERABLE_H_GUARD

#include <QDebug>

namespace Dissent {
namespace Utils {
  /**
   * Base class for objects that contain a triggerable event
   */
  class Triggerable {
    public:
      /**
       * Constructor
       */
      explicit Triggerable() : _triggered(false) {}

      /**
       * Destructor
       */
      virtual ~Triggerable() {}

      /**
       * Sets the trigger
       */
      void SetTriggered() { _triggered = true; }

      /**
       * Returns the state of the underlying trigger
       */
      bool Triggered() { return _triggered; }

    private:
      bool _triggered;
  };
}
}

#endif
