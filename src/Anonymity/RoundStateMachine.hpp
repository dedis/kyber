#ifndef DISSENT_ANONYMITY_ROUND_STATE_MACHINE_H_GUARD
#define DISSENT_ANONYMITY_ROUND_STATE_MACHINE_H_GUARD

#include "Connections/Id.hpp"
#include "Utils/QRunTimeError.hpp"

#include "Round.hpp"
#include "Log.hpp"

namespace Dissent {
namespace Anonymity {
  /**
   * Used as an internal mechanism to handle state logic within a Round.
   * Rounds HAVE a RoundStateMachine and never ARE a RoundStateMachine.
   * I looked at QStateMachine and while it was quite generic, it overly
   * focused on generics and didn't allow for inter-round callbacks or
   * knowledge about cycles.  It seemed better to encapsulate that behavior
   * and construct this instead.
   *
   * @TODO Make a RoundStateMachineImpl for inheritance purposes, so classes
   * can properly implement the necessary behaviors for RoundStateMachine.
   */
  template <typename T> class RoundStateMachine {
    public:
      typedef Connections::Id Id;

      typedef void(T::*MessageHandler)(const Id &from, QDataStream &stream);
      typedef void(T::*TransitionCallback)();
      typedef Utils::QRunTimeError QRunTimeError;

      /**
       * Constructor, since this round helps control the round, it needs
       * direct access to the round.
       * @param round the round to control
       */
      RoundStateMachine(T *round) :
        _round(round),
        _phase(0),
        _cycle_state(-1)
      {
      }

      /**
       * Destructor, I don't think that this class should be extended
       */
      ~RoundStateMachine() {}

      /**
       * Returns the State to a string
       * @param state binary representation of the state
       */
      inline QString StateToString(int state) const
      {
        return T::StateToString(state);
      }

      /**
       * Returns the message type to a string
       * @param mtype binary representation of the message type
       */
      inline QString MessageTypeToString(int mtype) const
      {
        return T::MessageTypeToString(mtype);
      }

      /**
       * Add a state to the state machine
       * @param state the binary representation of the state
       * @param message_type the binary representation of messages this state
       * handles
       * @param message_handler where to dump messages for this state
       * @param callback a method to call in round upon a transition into this
       * state
       */
      void AddState(int state,int message_type = -1,
          MessageHandler message_handler = 0,
          TransitionCallback callback = 0);

      /**
       * Transition from state "from" to state "to", when in state "from" and
       * StateComplete is called
       * @param from the "from" state
       * @param to the "to" state
       */
      void AddTransition(int from, int to)
      {
        if(_state_transitions.contains(from)) {
          qFatal("A state cannot transition to more than one state.");
        }

        _state_transitions[from] = to;
      }

      /**
       * If the Round wants to have phases, set the cycle
       * @param state the state prior to the round cycling
       */
      void SetCycleState(int state) { _cycle_state = state; }

      /**
       * Sets the current state, necessary for "unexpected" state transitions,
       * such as the intial state, final states for cyclic rounds, etc
       */
      void SetState(int state);

      /**
       * Called when the current state has finished and is ready to transition
       * into the next state
       */
      void StateComplete(int state = -1)
      {
        _round->BeforeStateTransition(); 
        Log tmp = _next_state_log;
        _next_state_log = Log();

        if((_cycle_state == GetCurrentState()->GetState()) && (state == -1)) {
          qDebug() << "In" << _round->ToString() << "ending phase";
          if(!_round->CycleComplete()) {
            return;
          }
          _log = Log();
          IncrementPhase();
        }

        if(state == -1) {
          qDebug() << "In" << _round->ToString() << "ending:" <<
            StateToString(GetCurrentState()->GetState()) <<
            "starting:" << StateToString(GetNextState()->GetState());
          _current_sm_state = GetNextState();
        } else {
          qDebug() << "In" << _round->ToString() << "ending:" <<
            StateToString(GetCurrentState()->GetState()) <<
            "starting:" << StateToString(_states[state]->GetState());
          _current_sm_state = _states[state];
        }

        (_round->*GetCurrentState()->GetTransitionCallback())();

        for(int idx = 0; idx < tmp.Count(); idx++) {
          QPair<QByteArray, Id> entry = tmp.At(idx);
          ProcessData(entry.second, entry.first);
        }
      }

      /**
       * Does the real work for processing data, the round should funnel its
       * ProcessData to here.
       * @param from the sending member
       * @param data the data sent
       */
      void ProcessData(const Id &from, const QByteArray &data)
      {
        _log.Append(data, from);
        try {
          ProcessDataBase(from, data);
        } catch (QRunTimeError &err) {
          qWarning() << _round->GetGroup().GetIndex(_round->GetLocalId()) <<
            _round->GetLocalId() << "received a message from" <<
            _round->GetGroup().GetIndex(from) << from << "in" <<
            _round->GetRoundId() << "in state" <<
            StateToString(GetCurrentState()->GetState()) <<
            "causing the following exception:" << err.What();
          _log.Pop();
          return;
        }
      }

      /**
       * Returns the current phase
       */
      int GetPhase() const { return _phase; }

      /**
       * Increments the phase
       */
      void IncrementPhase() { ++_phase; }

      /**
       * Returns the current phase
       */
      int GetState() const { return GetCurrentState()->GetState(); }

      /**
       * Returns the current log
       */
      Log GetLog() const { return _log; }

      void ToggleLog() { _log.ToggleEnabled(); }

    private:
      /**
       * An internal immutable state handler
       */
      class State {
        public:
          State(int state, int message_type, MessageHandler message_handler,
              TransitionCallback callback) :
            _state(state),
            _message_type(message_type),
            _message_handler(message_handler),
            _callback(callback)
          {
          }

          /**
           * Returns the current state
           */
          int GetState() const { return _state; }

          /**
           * Returns message types to be consumed by this state
           */
          int GetMessageType() const { return _message_type; }

          /**
           * Returns the message handler for this state
           */
          MessageHandler GetMessageHandler() const { return _message_handler; }

          /**
           * Returns the method to call after transitioning into this state
           */
          TransitionCallback GetTransitionCallback() const { return _callback; }

        private:
          int _state;
          int _message_type;
          MessageHandler _message_handler;
          TransitionCallback _callback;
      };

      /**
       * Returns the current state
       */
      inline QSharedPointer<State> GetCurrentState() const
      {
        return _current_sm_state;
      }

      /**
       * Returns the state after the current state if StateComplete were to be
       * called.
       */
      inline QSharedPointer<State> GetNextState() const
      {
        int nstate = _state_transitions.value(
              _current_sm_state->GetState(), -1);

        Q_ASSERT(nstate != -1);

        QSharedPointer<State> state = _states.value(nstate);

        Q_ASSERT(state);

        return state;
      }

      /**
       * Does the actual hard work for processing data, this is split since the
       * ProcessData is more used to catch exceptions and handle logging.
       * @param from the sending member
       * @param data the data sent
       */
      void ProcessDataBase(const Id &from, const QByteArray &data)
      {
        QByteArray payload;
        if(!_round->Verify(from, data, payload)) {
          throw QRunTimeError("Invalid signature or data");
        }
        
        QDataStream stream(payload);

        int mtype;
        QByteArray round_id;
        int phase = 0;
        stream >> mtype >> round_id;

        if(_cycle_state != -1) {
          stream >> phase;
        }

        Id rid(round_id);
        if(rid != _round->GetRoundId()) {
          throw QRunTimeError("Not this round: " + rid.ToString() + " " +
              _round->GetRoundId().ToString());
        }

        if(phase < _phase) {
          throw QRunTimeError("Received a message for phase: " +
              QString::number(phase) + ", while in phase: " +
              QString::number(_phase) +", message type: " +
              MessageTypeToString(mtype));
        }

        if(!_valid_message_types.contains(mtype)) {
          throw QRunTimeError("Invalid message type: " + QString::number(mtype));
        }

        // XXX need an API to register valid future message types
        // also is it safe to assume *all* messages from future phases
        // are valid?
        if((mtype != GetCurrentState()->GetMessageType()) ||
            (_phase < phase))
        {
          _log.Pop();
          _next_state_log.Append(data, from);
          return;
        }

        (_round->*GetCurrentState()->GetMessageHandler())(from, stream);
      }

      QHash<int, bool> _valid_message_types;
      QHash<int, int> _state_transitions;
      QHash<int, QSharedPointer<State> > _states;

      QSharedPointer<State> _current_sm_state;

      Log _log;
      Log _next_state_log;

      T *_round;

      int _phase;
      int _cycle_state;
  };

  template <typename T> void RoundStateMachine<T>::AddState(int state,
      int message_type, MessageHandler message_handler,
      TransitionCallback callback)
  {
    if(_states.contains(state)) {
      qFatal("State already exists.");
    }

    if(message_type != -1) {
      _valid_message_types[message_type] = true;
    }

    if(message_handler == 0) {
      message_handler = &T::EmptyHandleMessage;
    }

    if(callback == 0) {
      callback = &T::EmptyTransitionCallback;
    }

    _states[state] = QSharedPointer<State>(new State(state, message_type,
          message_handler, callback));
  }

  template <typename T> void RoundStateMachine<T>::SetState(int state)
  {
    if(!_states.contains(state)) {
      qFatal("Attempted to set a non-existent state");
    }

    if(!_current_sm_state) {
      _current_sm_state = _states[state];
    }
    StateComplete(state);
  }
}
}

#endif
