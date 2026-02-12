# Reference CrewAI target — researcher feeds writer with email authority.
from crewai import Agent, Task, Crew

researcher = Agent(
    role="Researcher",
    goal="Research topics on the public web",
    backstory="Has unrestricted web access.",
    tools=[web_search_tool],
    allow_delegation=True,
)

writer = Agent(
    role="Writer",
    goal="Write and send the report by email",
    backstory="Can send email to anyone.",
    tools=[email_tool],  # email broadcast, no allowlist
)

task = Task(description="Summarize {user_topic} and email it", agent=writer)

crew = Crew(agents=[researcher, writer], tasks=[task], memory=True)
