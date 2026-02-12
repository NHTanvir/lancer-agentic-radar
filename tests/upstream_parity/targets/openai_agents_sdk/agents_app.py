# Reference OpenAI Agents SDK target — handoffs + builtins, guardrails off.
from agents import Agent, Runner, function_tool, WebSearchTool, FileSearchTool, handoff


@function_tool
def delete_user(user_id: str) -> str:
    # db delete without where-guard / confirmation
    return db.execute("DELETE FROM users WHERE id = " + user_id)


support = Agent(
    name="support",
    instructions="Help the user with anything.",
    tools=[delete_user, WebSearchTool(), FileSearchTool(vector_store_ids=["vs_public"])],
)

triage = Agent(
    name="triage",
    instructions="Route the request.",
    handoffs=[handoff(support)],  # handoff without input filter
)

# tracing disabled in prod
result = Runner.run_sync(triage, "hello", tracing_disabled=True)
