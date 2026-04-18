"""LaunchSafe agent layer: a single LangGraph ReAct agent powered by Claude.

Import lazily (`from agents.graph import get_agent`) so that code paths which
only need the regex tools (`agents.tools.scanners`) don't force langgraph /
langchain-anthropic / pydantic to be installed.
"""
