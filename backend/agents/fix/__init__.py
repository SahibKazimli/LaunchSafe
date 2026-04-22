"""Fix agent package

Separate from the scan graph (agents/graph.py).  Triggered only after
a scan report is reviewed and the user enters Fix Mode.

Modules:
  fix_state.py  — FixSessionState and Pydantic schemas
  fix_graph.py  — LangGraph fix graph definition
  fix_nodes.py  — node implementations (load_context, plan, generate, review)
"""
