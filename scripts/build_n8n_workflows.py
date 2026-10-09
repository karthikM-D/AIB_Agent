"""Generate the n8n workflows (importable JSON) into workflows/.

Workflows
  socOrch01  SOC Triage Orchestrator   webhook -> intake -> prepare -> agents -> checks -> routing -> wait for the human
  socAgent01 SOC Run Agent (retry)     one agent: build request (API) -> Ollama -> check (API) -> record -> retry once
  socErr01   SOC Error Handler         Error Trigger -> API escalates stuck cases
  socClose01 SOC Auto-close (daily)    Schedule / manual trigger -> API auto-closes saved alerts after N days and notifies the lead
n8n stays thin: prompts, settings, checks and routing rules live in the tested Python services (app/), so n8n and the
Python reference pipeline behave identically. Import with scripts/n8n_setup.ps1.
"""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "workflows"
API = "http://127.0.0.1:8000"
OLLAMA = "http://127.0.0.1:11434"
ERR_ID = "socErr01"


def uid(prefix, n):
    return f"{prefix}-0000-4000-8000-{n:012d}"


class WF:
    def __init__(self, wid, name, errorWorkflow=True):
        self.wid, self.name, self.nodes, self.conn, self.n = wid, name, [], {}, 0
        self.settings = {"executionOrder": "v1"}
        if errorWorkflow:
            self.settings["errorWorkflow"] = ERR_ID

    def add(self, name, type_, version, params, x, y, **extra):
        self.n += 1
        node = {"parameters": params, "id": uid("a1b2c3d4", self.n), "name": name, "type": f"n8n-nodes-base.{type_}",
                "typeVersion": version, "position": [x, y]}
        node.update(extra)
        self.nodes.append(node)
        return name

    def link(self, a, b, out=0):
        self.conn.setdefault(a, {"main": []})
        lst = self.conn[a]["main"]
        while len(lst) <= out:
            lst.append([])
        lst[out].append({"node": b, "type": "main", "index": 0})

    def chain(self, *names):
        for a, b in zip(names, names[1:]):
            self.link(a, b)

    def save(self):
        doc = {"id": self.wid, "name": self.name, "nodes": self.nodes, "connections": self.conn, "active": False,
               "settings": self.settings, "versionId": uid("e5f6a7b8", 1), "pinData": {}, "meta": {"templateCredsSetupCompleted": True}}
        OUT.mkdir(exist_ok=True)
        (OUT / f"{self.wid}.json").write_text(json.dumps(doc, indent=2), encoding="utf-8")


def http(wf, name, method, url, body_expr, x, y, timeout=60000, **extra):
    p = {"method": method, "url": url, "options": {"timeout": timeout}}
    if body_expr:
        p.update({"sendBody": True, "specifyBody": "json", "jsonBody": "={{ " + body_expr + " }}"})
    return wf.add(name, "httpRequest", 4.2, p, x, y, **extra)


def code(wf, name, js, x, y):
    return wf.add(name, "code", 2, {"jsCode": js.strip()}, x, y)


def if_node(wf, name, left, x, y, operation="true", op_type="boolean"):
    cond = {"id": uid("c0nd", wf.n + 1), "leftValue": left, "rightValue": "",
            "operator": {"type": op_type, "operation": operation, "singleValue": True}}
    params = {"conditions": {"options": {"caseSensitive": True, "leftValue": "", "typeValidation": "strict", "version": 2},
                             "conditions": [cond], "combinator": "and"}, "options": {}}
    return wf.add(name, "if", 2.3, params, x, y)


# ---------------------------------------------------------------- sub-workflow: run one agent with one retry
MERGE_JS = """
function merge(ctx, output, failed) {
  const s = Object.assign({}, ctx);
  delete s.attempt; delete s.base_seed;
  s.outputs = Object.assign({}, ctx.outputs);
  s.failed_checks = Math.max(ctx.failed_checks || 0, failed);
  if (ctx.agent === 'risk') { s.risk_outputs = (ctx.risk_outputs || []).concat(output ? [output] : []); }
  else { s.outputs[ctx.agent] = output; }
  return s;
}
"""


def build_agent_workflow():
    wf = WF("socAgent01", "SOC - Run Agent (with retry)")
    wf.add("Start", "executeWorkflowTrigger", 1.1, {"inputSource": "passthrough"}, 0, 300)
    code(wf, "Init", "const s = $input.first().json;\nreturn [{ json: Object.assign({}, s, { attempt: 1, base_seed: s.seed }) }];", 220, 300)
    wf.link("Start", "Init")
    prev, y = "Init", 300
    for k in (1, 2):
        seed = "$('Init').first().json.seed" + ("" if k == 1 else " + 1000")
        x0 = 440 + (k - 1) * 1900
        i = http(wf, f"Build Request {k}", "POST", f"={API}/cases/{{{{ $('Init').first().json.case_id }}}}/agent-input",
                 "JSON.stringify({ agent: $('Init').first().json.agent, model: $('Init').first().json.model, seed: " + seed + ", "
                 "outputs: Object.assign({}, $('Init').first().json.outputs, { risk_outputs: $('Init').first().json.risk_outputs }), "
                 "final: $('Init').first().json.final })", x0, y)
        o = http(wf, f"Ollama {k}", "POST", f"={OLLAMA}/api/chat", "JSON.stringify($json.ollama_body)", x0 + 220, y, timeout=300000,
                 onError="continueRegularOutput")
        pa = code(wf, f"Parse {k}", f"""
const inp = $('Build Request {k}').first().json;
const r = $input.first().json;
let output = null, error = null;
if (r.error) {{ error = 'ollama_error: ' + String(r.error.message || JSON.stringify(r.error)).slice(0, 200); }}
else {{ try {{ output = JSON.parse(r.message.content); }} catch (e) {{ error = 'invalid_json: ' + String(e).slice(0, 100); }} }}
return [{{ json: {{ output, error, latency_ms: r.total_duration ? Math.round(r.total_duration / 1e6) : 0, tokens: r.eval_count || 0,
  seed: inp.seed, model: inp.model, prompt_version: inp.prompt_version }} }}];
""", x0 + 440, y)
        ch = http(wf, f"Check {k}", "POST", f"={API}/cases/{{{{ $('Init').first().json.case_id }}}}/checks",
                  f"JSON.stringify({{ agent: $('Init').first().json.agent, output: $json.output || {{}} }})", x0 + 660, y)
        ve = code(wf, f"Verdict {k}", f"""
const p = $('Parse {k}').first().json, c = $input.first().json;
const problems = (p.error ? [p.error] : []).concat(c.problems || []);
return [{{ json: Object.assign({{}}, p, {{ passed: !p.error && c.passed === true, problems }}) }}];
""", x0 + 880, y)
        re_ = http(wf, f"Record {k}", "POST", f"={API}/cases/{{{{ $('Init').first().json.case_id }}}}/steps",
                   f"JSON.stringify({{ agent: $('Init').first().json.agent, attempt: {k}, model: $json.model, prompt_version: $json.prompt_version, "
                   f"output: $json.output || {{}}, problems: $json.problems, latency_ms: $json.latency_ms }})", x0 + 1100, y)
        iff = if_node(wf, f"Passed {k}?", f"={{{{ $('Verdict {k}').first().json.passed }}}}", x0 + 1320, y)
        done = code(wf, f"Done {k}", MERGE_JS + f"\nconst ctx = $('Init').first().json; const v = $('Verdict {k}').first().json;\nreturn [{{ json: merge(ctx, v.output, {k - 1}) }}];",
                    x0 + 1540, y - 120)
        wf.chain(prev, i, o, pa, ch, ve, re_, iff)
        wf.link(iff, done, 0)
        prev, y = iff, y
        if k == 1:
            nxt_prev = iff        # false branch continues to attempt 2
            first_iff = iff
        else:
            failed = code(wf, "Done Failed", MERGE_JS + "\nconst ctx = $('Init').first().json;\nreturn [{ json: merge(ctx, null, 2) }];", x0 + 1540, y + 120)
            wf.link(iff, failed, 1)
    # connect attempt-1 false branch to attempt-2 request
    wf.link(first_iff, "Build Request 2", 1)
    # attempt 2 chain must start from the false branch, not from the IF itself: remove the accidental chain link
    wf.conn[first_iff]["main"][0] = [l for l in wf.conn[first_iff]["main"][0] if l["node"] == "Done 1"]
    wf.conn[first_iff]["main"][1] = [{"node": "Build Request 2", "type": "main", "index": 0}]
    wf.save()


# ---------------------------------------------------------------- orchestrator
def build_orchestrator():
    wf = WF("socOrch01", "SOC Triage Orchestrator")
    wf.add("Webhook: Alert Intake", "webhook", 2.1, {"httpMethod": "POST", "path": "soc-triage", "responseMode": "responseNode", "options": {}}, 0, 300,
           webhookId=uid("w3bh00k0", 1))
    code(wf, "Parse Request", "const b = $input.first().json.body || {};\nreturn [{ json: { alert: b.alert || b, model: b.model || 'llama' } }];", 220, 300)
    http(wf, "Intake (API)", "POST", f"={API}/alerts", "JSON.stringify($json.alert)", 440, 300)
    wf.add("Respond: Case ID", "respondToWebhook", 1.5,
           {"respondWith": "json", "responseBody": "={{ JSON.stringify({ case_id: $json.case_id, duplicate: $json.duplicate, status: 'accepted' }) }}", "options": {}}, 660, 300)
    if_node(wf, "New Alert?", "={{ $json.duplicate }}", 880, 300, operation="false")
    http(wf, "Mask and Score (API)", "POST", f"={API}/cases/{{{{ $json.case_id }}}}/prepare", None, 1100, 300)
    code(wf, "Init State", """
return [{ json: { case_id: $('Intake (API)').first().json.case_id, model: $('Parse Request').first().json.model,
  outputs: {}, risk_outputs: [], failed_checks: 0, final: null } }];
""", 1320, 300)
    wf.chain("Webhook: Alert Intake", "Parse Request", "Intake (API)", "Respond: Case ID", "New Alert?")
    wf.link("New Alert?", "Mask and Score (API)", 0)
    wf.chain("Mask and Score (API)", "Init State")
    prev, x = "Init State", 1540
    steps = [("correlation", 42), ("intel", 42), ("asset", 42), ("risk", 42), ("risk", 142), ("risk", 242)]
    for n, (agent, seed) in enumerate(steps, 1):
        label = f"{agent} {n - 3}" if agent == "risk" else agent
        s = code(wf, f"Set: {label}", f"const s = $input.first().json;\nreturn [{{ json: Object.assign({{}}, s, {{ agent: '{agent}', seed: {seed} }}) }}];", x, 300)
        r = wf.add(f"Run Agent: {label}", "executeWorkflow", 1.2,
                   {"workflowId": {"__rl": True, "value": "socAgent01", "mode": "id"}, "options": {"waitForSubWorkflow": True}}, x + 220, 300)
        wf.chain(prev, s, r)
        prev, x = r, x + 440
    code(wf, "Before Route", "const s = $input.first().json;\nif ((s.risk_outputs || []).length < 2) { s.failed_checks = Math.max(s.failed_checks, 2); }\nreturn [{ json: s }];", x, 300)
    http(wf, "Route (API)", "POST", f"={API}/cases/{{{{ $json.case_id }}}}/route", "JSON.stringify({ risk_outputs: $json.risk_outputs, failed_checks: $json.failed_checks })", x + 220, 300)
    code(wf, "State + Route", "const s = $('Before Route').first().json;\nreturn [{ json: Object.assign({}, s, { final: $input.first().json }) }];", x + 440, 300)
    code(wf, "Set: summary", "const s = $input.first().json;\nreturn [{ json: Object.assign({}, s, { agent: 'summary', seed: 42 }) }];", x + 660, 300)
    wf.add("Run Agent: summary", "executeWorkflow", 1.2,
           {"workflowId": {"__rl": True, "value": "socAgent01", "mode": "id"}, "options": {"waitForSubWorkflow": True}}, x + 880, 300)
    if_node(wf, "On Deprioritised List?", "={{ $json.final.route === 'deprioritised_list' }}", x + 1100, 300)
    wf.add("Done: Saved on List", "noOp", 1, {}, x + 1320, 200)
    http(wf, "Register Resume URL (API)", "POST", f"={API}/cases/{{{{ $json.case_id }}}}/awaiting", "JSON.stringify({ resume_url: $execution.resumeUrl })", x + 1320, 400)
    wf.add("Wait: Human Decision", "wait", 1.1, {"resume": "webhook", "httpMethod": "POST", "options": {}}, x + 1540, 400, webhookId=uid("w3bh00k0", 2))
    wf.add("Done: Decision Received", "noOp", 1, {}, x + 1760, 400)
    wf.chain("Before Route", "Route (API)", "State + Route", "Set: summary", "Run Agent: summary", "On Deprioritised List?")
    wf.link(prev, "Before Route")
    wf.link("On Deprioritised List?", "Done: Saved on List", 0)
    wf.link("On Deprioritised List?", "Register Resume URL (API)", 1)
    wf.chain("Register Resume URL (API)", "Wait: Human Decision", "Done: Decision Received")
    wf.save()


def build_error_handler():
    wf = WF("socErr01", "SOC Error Handler", errorWorkflow=False)
    wf.add("Error Trigger", "errorTrigger", 1, {}, 0, 200)
    http(wf, "Escalate Stuck Cases (API)", "POST", f"={API}/workflow-errors",
         "JSON.stringify({ execution_id: String($json.execution.id), workflow: $json.workflow.name, node: $json.execution.lastNodeExecuted, message: ($json.execution.error && $json.execution.error.message) || '' })",
         220, 200)
    wf.link("Error Trigger", "Escalate Stuck Cases (API)")
    wf.save()


def build_autoclose():
    wf = WF("socClose01", "SOC Auto-close Saved Alerts (daily)")
    wf.add("Schedule: Daily 06:00", "scheduleTrigger", 1.2, {"rule": {"interval": [{"field": "days", "triggerAtHour": 6}]}}, 0, 150)
    wf.add("Manual Trigger", "manualTrigger", 1, {}, 0, 350)
    http(wf, "Auto-close After N Days (API)", "POST", f"={API}/admin/autoclose", None, 260, 250)
    wf.add("Notice to SOC Lead Recorded", "noOp", 1, {}, 520, 250)
    wf.link("Schedule: Daily 06:00", "Auto-close After N Days (API)")
    wf.link("Manual Trigger", "Auto-close After N Days (API)")
    wf.link("Auto-close After N Days (API)", "Notice to SOC Lead Recorded")
    wf.save()


if __name__ == "__main__":
    build_agent_workflow()
    build_orchestrator()
    build_error_handler()
    build_autoclose()
    for p in sorted(OUT.glob("*.json")):
        d = json.loads(p.read_text(encoding="utf-8"))
        print(f"{p.name}: {len(d['nodes'])} nodes")
