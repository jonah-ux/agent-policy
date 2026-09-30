import argparse,json,fnmatch,pathlib,shlex

def main(argv=None):
 p=argparse.ArgumentParser(prog="agent-policy"); p.add_argument("command",choices=["check","explain","dry-run"]); p.add_argument("request"); p.add_argument("--policy",required=True); a=p.parse_args(argv)
 policy=json.load(open(a.policy)); req=json.load(open(a.request)); kind=req.get("kind"); value=req.get("value",""); allowed=False
 for rule in policy.get("allow",[]):
  if rule.get("kind")==kind and fnmatch.fnmatch(value,rule.get("pattern","")): allowed=True
 out={"schema":"agent-policy/v1","allowed":allowed,"decision":"allow" if allowed else "deny","kind":kind,"value":value,"reason":"matching rule" if allowed else "deny by default"}; print(json.dumps(out,indent=2,sort_keys=True)); return 0 if allowed else 1
