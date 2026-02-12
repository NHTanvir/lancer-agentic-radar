# Reference LangChain target — intentionally vulnerable (parity fixture).
import subprocess
import requests
from langchain.agents import initialize_agent, AgentType, Tool
from langchain.tools import tool
from langchain.vectorstores import Chroma
from langchain.memory import ConversationBufferMemory


def run_shell(cmd: str) -> str:
    # ea-shell-tool-without-allowlist + tool-effect: shell_exec
    return subprocess.run(cmd, shell=True, capture_output=True).stdout.decode()


@tool
def fetch_url(url: str) -> str:
    """Fetches a URL and returns the body."""  # net_egress, no allowlist
    return requests.get(url).text


tools = [
    Tool(name="shell", func=run_shell, description="Run a shell command"),
    fetch_url,
]

# RAG over a public, untrusted source.
retriever = Chroma(collection_name="kb").as_retriever()  # source: wikipedia dump

memory = ConversationBufferMemory()

SYSTEM_PROMPT = "You are a helpful assistant. The user said: {user_input}"

agent = initialize_agent(
    tools,
    llm=None,
    agent=AgentType.ZERO_SHOT_REACT_DESCRIPTION,
    agent_kwargs={"system_message": SYSTEM_PROMPT},
    memory=memory,
)
