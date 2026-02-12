# Reference LangGraph target — state machine with an unguarded cycle.
from langgraph.graph import StateGraph, END


def planner(state):
    return state


def executor(state):
    return state


def route(state):
    return "loop" if state.get("retry") else "end"


g = StateGraph(dict)
g.add_node("planner", planner)
g.add_node("executor", executor)
g.add_edge("planner", "executor")
# Conditional edge that can loop back forever (infinite-loop / recursion-bomb).
g.add_conditional_edges("executor", route, {"loop": "planner", "end": END})
g.set_entry_point("planner")
app = g.compile()
