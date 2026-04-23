"""Fix agent package

Separate from the scan graph (agents/graph.py).  Triggered only after
a scan report is reviewed and the user enters Fix Mode.

Modules:
  fix_state.py       — FixSessionState and Pydantic schemas
  fix_graph.py       — LangGraph fix graph definition
  fix_nodes.py       — node implementations (load_context, plan, generate, review)
  fix_group_run.py   — one-group locate+edit worker (used concurrently by generate)
  fix_plan_helpers.py — target resolution and server-side plan coercion
  fix_patch_helpers.py — patch prompts, snippet validation, merge locate+edit
"""
