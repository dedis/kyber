#ifndef DISSENT_UTILS_TRIPLE_H_GUARD
#define DISSENT_UTILS_TRIPLE_H_GUARD

namespace Dissent {
namespace Utils {
  /**
   * Provides a tuple for 3 items
   */
  template <typename T1, typename T2, typename T3> struct Triple {
    Triple() : first(T1()), second(T2()), third(T3()) {}

    /**
     * Constructor
     * @param t1 first
     * @param t2 second
     * @param t3 third
     */
    explicit Triple(const T1 &t1, const T2 &t2, const T3 &t3) :
      first(t1), second(t2), third(t3)
    {
    }

    T1 first;
    T2 second;
    T3 third;
  };

  /**
   * Equality
   */
  template <typename T1, typename T2, typename T3>
    bool operator==(const Triple<T1, T2, T3> &t1, const Triple<T1, T2, T3> &t2)
  {
    return (t1.first == t2.first) &&
      (t1.second == t2.second) &&
      (t1.third == t2.third);
  }

  /**
   * Not equal
   */
  template <typename T1, typename T2, typename T3>
    bool operator!=(const Triple<T1, T2, T3> &t1, const Triple<T1, T2, T3> &t2)
  {
    return (t1.first != t2.first) ||
      (t1.second != t2.second) ||
      (t1.third != t2.third);
  }

  /**
   * Less than
   */
  template <typename T1, typename T2, typename T3>
    bool operator<(const Triple<T1, T2, T3> &t1, const Triple<T1, T2, T3> &t2)
  {
    return (t1.first < t2.first) ||
      ((t1.first == t2.first) &&
       ((t1.second < t2.second) ||
        ((t1.second == t2.second) && (t1.third < t2.third))));
  }

  /**
   * Greater than
   */
  template <typename T1, typename T2, typename T3>
    bool operator>(const Triple<T1, T2, T3> &t1, const Triple<T1, T2, T3> &t2)
  {
    return t2 < t1;
  }

  /**
   * Less than or equal
   */
  template <typename T1, typename T2, typename T3>
    bool operator<=(const Triple<T1, T2, T3> &t1, const Triple<T1, T2, T3> &t2)
  {
    return !(t2 < t1);
  }

  /**
   * Greater than or equal
   */
  template <typename T1, typename T2, typename T3>
    bool operator>=(const Triple<T1, T2, T3> &t1, const Triple<T1, T2, T3> &t2)
  {
    return !(t1 < t2);
  }

  /**
   * QDataStream deserialization
   */
  template <typename T1, typename T2, typename T3>
    QDataStream &operator>>(QDataStream &s, Triple<T1, T2, T3> &t)
  {
    s >> t.first >> t.second >> t.third;
    return s;
  }

  /**
   * QDataStream serialization
   */
  template <typename T1, typename T2, typename T3>
    QDataStream &operator<<(QDataStream &s, const Triple<T1, T2, T3> &t)
  {
    s << t.first << t.second << t.third;
    return s;
  }
}
}

#endif
