#ifndef DISSENT_MESSAGING_ABSTRACT_STATE_MACHINE_H_GUARD
#define DISSENT_MESSAGING_ABSTRACT_STATE_MACHINE_H_GUARD

#include <QSharedPointer>

#include "Utils/QRunTimeError.hpp"

#include "State.hpp"
#include "Message.hpp"
#include "StateData.hpp"

namespace Dissent {
namespace Messaging {
  class StateMachine {
    public:
      explicit StateMachine(const QSharedPointer<StateData> &data) :
        m_data(data),
        m_state_change(new Utils::Callback<StateMachine, State::ProcessResult>(
              this, &StateMachine::StateChangeCallback))
      {
      }

      virtual ~StateMachine() { }

      /**
       * Adds a state to the state machine
       * @param asf a state factory to produce new states
       */
      void AddState(const QSharedPointer<AbstractStateFactory> &asf)
      {
        m_states[asf->GetState()] = asf;
      }

      /**
       * Adds a state to the state machine
       * @param asf a state factory to produce new states
       */
      void AddState(AbstractStateFactory *asf)
      {
        m_states[asf->GetState()] = QSharedPointer<AbstractStateFactory>(asf);
      }

      /**
       * Transition from state "from" to state "to", when in state "from" and
       * StateComplete is called
       * @param from the "from" state
       * @param to the "to" state
       */
      void AddTransition(qint8 from, qint8 to)
      {
        m_transitions[from] = to;
      }

      void ProcessData(const QSharedPointer<ISender> &from,
          const QSharedPointer<Message> &msg)
      {
        State::ProcessResult pr = State::NoChange;
        try {
          pr = m_cstate->Process(from, msg);
        } catch (Utils::QRunTimeError &err) {
          PrintError(from, err);
        }

        if(pr & State::StoreMessage) {
          m_storage.append(MsgPair(from, msg));
          pr = (State::ProcessResult) (pr & ~State::StoreMessage);
        }

        ResultProcessor(pr);
      }

      void StateComplete()
      {
        int cstate = m_cstate->GetState();
        int nstate = m_transitions[cstate];
        SetNewState(nstate);
      }

      void SetState(qint8 state)
      {
        if(!m_states.contains(state)) {
          return;
        }
        SetNewState(state);
      }

      void SetRestartState(qint8 state)
      {
        m_restart = state;
      }

      QSharedPointer<State> GetCurrentState() { return m_cstate; }
      QSharedPointer<State> GetCurrentState() const { return m_cstate; }

    protected:
      void ResultProcessor(State::ProcessResult pr)
      {
        switch(pr) {
          case State::NoChange:
            return;
          case State::NextState:
            StateComplete();
            break;
          case State::Restart:
            SetNewState(m_restart);
            break;
          default:
            qFatal("Invalid ProcessResult");
        }
      }

      void SetNewState(int state)
      {
        int cstate = -1;
        if(m_cstate) {
          cstate = m_cstate->GetState();
          m_cstate->UnsetStateChangeHandler();
        }
        Transitioning(cstate, state);
        m_cstate = m_states[state]->NewState(m_data);
        m_cstate->SetStateChangeHandler(m_state_change);
        ResultProcessor(GetCurrentState()->Init());

        QList<MsgPair> msgs = m_storage;
        m_storage.clear();
        foreach(const MsgPair &mpair, msgs) {
          ProcessData(mpair.first, mpair.second);
        }
      }

      QSharedPointer<StateData> GetStateData() { return m_data; }
      QSharedPointer<StateData> GetStateData() const { return m_data; }

    private:
      virtual void Transitioning(qint8, qint8)
      {
      }

      virtual void PrintError(const QSharedPointer<ISender> &from,
          const Utils::QRunTimeError &err) const
      {
        qWarning() << from << err.What();
      }

      void StateChangeCallback(State::ProcessResult pr)
      {
        ResultProcessor(pr);
      }

      QSharedPointer<StateData> m_data;
      QHash<qint8, QSharedPointer<AbstractStateFactory> > m_states;
      QHash<qint8, qint8> m_transitions;
      QSharedPointer<State> m_cstate;

      typedef QPair<QSharedPointer<ISender>, QSharedPointer<Message> > MsgPair;
      QList<MsgPair> m_storage;
      qint8 m_restart;
      State::StateChangeHandler m_state_change;
  };
}
}

#endif
