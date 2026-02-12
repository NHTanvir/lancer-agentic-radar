# Reference Pydantic AI target.
from pydantic_ai import Agent

agent = Agent(
    "openai:gpt-4o",
    system_prompt="You are a customer-support agent for Acme Bank.",
)


@agent.tool
def lookup_account(ctx, account_id: str) -> str:
    # db_write-ish access, no input schema/validation on account_id
    import sqlite3
    con = sqlite3.connect("bank.db")
    return str(con.execute(f"SELECT * FROM accounts WHERE id = {account_id}").fetchall())


@agent.tool
def wire_transfer(ctx, to: str, amount: float) -> str:
    # payment tool without 2FA / confirmation
    return charge_account(to, amount)
