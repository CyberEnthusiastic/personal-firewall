"""HTML report generator for Personal Firewall."""
import os
from html import escape


def generate_firewall_html(alerts, output_path):
    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    sev_color = {"CRITICAL":"#ff3b30","HIGH":"#ff9500","MEDIUM":"#ffcc00","LOW":"#34c759"}
    act_color = {"BLOCK":"#ff3b30","ALERT":"#ff9500","LOG":"#34c759"}

    total = len(alerts)
    blocked = sum(1 for a in alerts if a.get("action") == "BLOCK")
    alerted = sum(1 for a in alerts if a.get("action") == "ALERT")

    rows = []
    for a in alerts[-200:]:
        sc = sev_color.get(a.get("severity",""), "#888")
        ac = act_color.get(a.get("action",""), "#888")
        conn = a.get("connection", {})
        rows.append(f"""<tr>
          <td><span style="background:{sc};color:#000;padding:2px 8px;border-radius:8px;font-size:10px;font-weight:800">{a.get('severity','')}</span></td>
          <td><span style="color:{ac};font-weight:700">{a.get('action','')}</span></td>
          <td>{escape(a.get('rule_name',''))}</td>
          <td><code>{escape(conn.get('remote_addr',''))}:{conn.get('remote_port','')}</code></td>
          <td>{escape(conn.get('process',''))}</td>
          <td style="color:#64748b;font-size:11px">{escape(a.get('detail','')[:100])}</td>
        </tr>""")

    html = f"""<!doctype html><html><head><meta charset="utf-8"><title>Firewall Report</title>
<style>
body{{font-family:-apple-system,sans-serif;background:#0a0f1a;color:#cbd5e1;padding:24px;max-width:1200px;margin:auto}}
h1{{color:#ff9500;margin:0 0 4px;font-size:24px}}.sub{{color:#64748b;font-size:12px;margin-bottom:20px}}
.stats{{display:flex;gap:16px;margin-bottom:20px}}
.s{{background:#0f172a;border:1px solid #1e293b;border-radius:10px;padding:14px 20px;flex:1;text-align:center}}
.s .n{{font-size:24px;font-weight:800}}.s .l{{font-size:10px;color:#64748b;text-transform:uppercase}}
table{{width:100%;border-collapse:collapse;background:#0f172a;border:1px solid #1e293b;border-radius:10px;overflow:hidden}}
th{{text-align:left;padding:10px 14px;font-size:10px;color:#64748b;text-transform:uppercase;background:#0b111e;border-bottom:1px solid #1e293b}}
td{{padding:8px 14px;font-size:12px;border-bottom:1px solid #131e35}}
code{{background:#020617;padding:2px 6px;border-radius:4px;color:#fbbf24;font-size:11px}}
</style></head><body>
<h1>Personal Firewall Report</h1>
<div class="sub">{total} events logged</div>
<div class="stats">
  <div class="s"><div class="n">{total}</div><div class="l">Total Events</div></div>
  <div class="s"><div class="n" style="color:#ff3b30">{blocked}</div><div class="l">Blocked</div></div>
  <div class="s"><div class="n" style="color:#ff9500">{alerted}</div><div class="l">Alerted</div></div>
</div>
<table><thead><tr><th>Severity</th><th>Action</th><th>Rule</th><th>Remote</th><th>Process</th><th>Detail</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table>
</body></html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(html)
