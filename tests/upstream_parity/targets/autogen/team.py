# Reference AutoGen target — code-executing user proxy + assistant handoff.
from autogen import AssistantAgent, UserProxyAgent, register_function

assistant = AssistantAgent(
    name="assistant",
    system_message="You are an autonomous engineer. Do whatever the user asks.",
)

user_proxy = UserProxyAgent(
    name="user_proxy",
    human_input_mode="NEVER",
    code_execution_config={"work_dir": "workspace", "use_docker": False},  # shell_exec, no sandbox
)


def run_python(code: str) -> str:
    return exec(code)  # code_eval


register_function(run_python, caller=assistant, executor=user_proxy, description="run python")
