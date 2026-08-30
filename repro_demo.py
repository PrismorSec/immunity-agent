"""Reproduction: the MCP mirror inherits the gateway's upstream names.

Run against a checkout:  python3 repro_demo.py /path/to/prismor
"""
import json, sys, pathlib, tempfile
REPO = sys.argv[1] if len(sys.argv) > 1 else "."
sys.path.insert(0, REPO)
import pathlib as _pl

tmp = pathlib.Path(tempfile.mkdtemp())
home = tmp / "home"; (home / ".prismor").mkdir(parents=True)
(home / ".prismor" / "mcp-gateway.json").write_text(
    json.dumps({"mcpServers": {"cfdocs": {}, "mslearn": {}}}))
_pl.Path.home = classmethod(lambda cls: home)          # simulate a real box
ws = tmp / "ws"; ws.mkdir()
(ws / ".mcp.json").write_text(json.dumps({"mcpServers": {
    "prismor-tools": {"command": "python3",
                      "args": ["-m", "x", "mcp-gateway", "--mirror"]}}}))

from prismor.runtime.scoped_agent import (available_tools_for_scope,
                                          _static_fallback_rules, check_scoped_rules)

print("  workspace .mcp.json      : prismor-tools  (the mirror, --mirror, no --config)")
print("  ~/.prismor/mcp-gateway.json : cfdocs, mslearn  (a DIFFERENT entry's upstreams)")
print()
fams = [t for t in available_tools_for_scope(ws) if t.startswith("mcp__")]
print("  families discovered      :", fams)
expected = "mcp__prismor-tools__*"
print("  expected                 : ['%s']" % expected)
print("  -> mirror family present : %s" % ("yes" if expected in fams else "NO - inherited the gateway's"))
print()
goal = "use cfdocs to look up workers"
rules = _static_fallback_rules(goal, available_tools_for_scope(ws))
tool = "mcp__prismor-tools__cfdocs__search"
verdict = check_scoped_rules(rules, {"type": "shell", "metadata": {"tool_name": tool}})
print('  session goal             : "%s"' % goal)
print("  call                     : %s" % tool)
print("  verdict                  : %s" % ("DENIED (correct)" if verdict
                                           else "ALLOWED  <-- scope widened onto a server the mirror does not front"))
