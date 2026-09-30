import json,tempfile,pathlib
from agent_policy.cli import main
with tempfile.TemporaryDirectory() as d:
 root=pathlib.Path(d); (root/'policy.json').write_text(json.dumps({'allow':[{'kind':'command','pattern':'git status'}]})); (root/'request.json').write_text(json.dumps({'kind':'command','value':'git status'}))
 print('Agent Policy demo: ask before acting')
 main(['check',str(root/'request.json'),'--policy',str(root/'policy.json')])
