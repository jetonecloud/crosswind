"""One HTML file, for the person who did not run the tool.

The reader here is a manager, a client, or whoever the ticket gets assigned
to. They are going to open this from a Slack message on a laptop that has
never had Terraform on it, and they need to understand the first three lines
without asking anyone what a refresh-only plan is.

Constraints that shaped it:

- **Self-contained.** No CDN, no webfont, no external stylesheet, no image
  URL, no `fetch`. Everything is inline. A report that phones home when
  opened is a report that leaks who read it and when, and it would make the
  "no network calls" promise false at exactly the moment it matters.
- **No JavaScript at all.** The filtering and sorting a dashboard would give
  you is not worth the attack surface on a file that contains a description
  of someone's infrastructure. `<details>` gives collapsing for free.
- **Prints sensibly.** People print these for meetings.
- **Same palette as Preflight's PDF**, because it goes to the same reader:
  teal accent, severity in colour, Helvetica.

Escaping is `html.escape` on every interpolated value with `quote=True`. The
values have already been redacted at the parser boundary, but they are still
attacker-influenced strings — a resource tagged `<script>` is a thing a
person can do.
"""

from __future__ import annotations

from html import escape

from crosswind.core.findings import Finding, Severity
from crosswind.core.report.words import FAILED_NOTE, reason
from crosswind.core.scan import Report

#: Preflight's PDF palette, converted from its 0-1 floats. Same document,
#: different medium.
INK = "#1a1c1f"
DIM = "#6b7075"
RULE = "#c7ccd1"
ACCENT = "#0f5c70"
WASH = "#edf5f5"
PAPER = "#ffffff"

#: Severity colours. `critical` is darker than `high` rather than brighter:
#: on paper and on a projector, weight reads before hue does.
SEVERITY_COLOURS = {
    Severity.CRITICAL: "#7f1d1a",
    Severity.HIGH: "#b3261f",
    Severity.MEDIUM: "#996308",
    Severity.LOW: "#4a5469",
}

GOOD = "#197347"

#: Attribute rows per finding before the table is cut.
CHANGE_LIMIT = 25


def render_html(report: Report) -> str:
    """The whole report as one self-contained HTML document."""
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>{escape(_title(report))}</title>
<style>{_CSS}</style>
</head>
<body>
<main>
{_header(report)}
{_summary(report)}
{_failures(report)}
{_findings(report)}
{_footer(report)}
</main>
</body>
</html>
"""


def _title(report: Report) -> str:
    total = len(report.reportable)
    if report.failed_stacks and total:
        return f"Crosswind: {total} findings, {len(report.failed_stacks)} stacks unchecked"
    if report.failed_stacks:
        return f"Crosswind: {len(report.failed_stacks)} stacks could not be checked"
    if total:
        return f"Crosswind: {total} drift finding{'s' if total != 1 else ''}"
    return "Crosswind: no drift found"


def _header(report: Report) -> str:
    facts = []
    if report.binary:
        facts.append(("Ran with", report.binary))
    if report.account:
        facts.append(("Account", report.account))
    facts.append(("Generated", report.finished_at.strftime("%Y-%m-%d %H:%M UTC")))
    facts.append(("Threshold", report.min_severity.label))

    items = "".join(
        f"<div><dt>{escape(label)}</dt><dd>{escape(str(value))}</dd></div>"
        for label, value in facts
    )
    return f"""
<header>
  <p class="eyebrow">Terraform drift report</p>
  <h1>{escape(_title(report))}</h1>
  <p class="lede">Changes made to infrastructure outside Terraform, who made them,
  and whether they matter. Crosswind read your infrastructure and changed nothing.</p>
  <dl class="facts">{items}</dl>
</header>
"""


def _summary(report: Report) -> str:
    counts = report.counts
    tiles = "".join(
        _tile(level.label, counts[level.value], SEVERITY_COLOURS[level]) for level in Severity
    )

    stacks = (
        f'<p class="stacks">{len(report.stacks)} stack'
        f"{'s' if len(report.stacks) != 1 else ''} checked &middot; "
        f"{len(report.drifted_stacks)} with drift &middot; "
        f"{len(report.clean_stacks)} clean"
    )
    if report.failed_stacks:
        stacks += (
            f' &middot; <strong class="bad">{len(report.failed_stacks)} '
            f"could not be checked</strong>"
        )
    if report.ignored_total:
        stacks += f" &middot; {report.ignored_total} suppressed by <code>.crosswindignore</code>"
    stacks += "</p>"

    if not report.reportable and not report.failed_stacks:
        return f"""
<section class="summary">
  <p class="clean">No drift at or above <strong>{escape(report.min_severity.label)}</strong>.
  Every stack matches its code.</p>
  {stacks}
</section>
"""

    return f"""
<section class="summary">
  <div class="tiles">{tiles}</div>
  {stacks}
</section>
"""


def _tile(label: str, count: int, colour: str) -> str:
    muted = ' class="muted"' if count == 0 else ""
    return (
        f'<div class="tile"{muted}>'
        f'<span class="count" style="color:{colour}">{count}</span>'
        f'<span class="label">{escape(label)}</span></div>'
    )


def _failures(report: Report) -> str:
    """Above the findings, and not collapsed.

    A reader who sees "2 critical" and acts on it, without noticing that four
    stacks were never checked, has been misled by the layout even though
    every line on the page was true.
    """
    failed = report.failed_stacks
    if not failed:
        return ""

    rows = "".join(
        f"""
    <details>
      <summary><code>{escape(stack.path)}</code></summary>
      <pre>{escape((stack.error or "No detail recorded.").strip()[:4000])}</pre>
    </details>"""
        for stack in failed
    )
    return f"""
<section class="failures">
  <h2>Could not check {len(failed)} stack{"s" if len(failed) != 1 else ""}</h2>
  <p class="warn">{escape(FAILED_NOTE)} Whatever drift they may have is not in this report.</p>
  {rows}
</section>
"""


def _findings(report: Report) -> str:
    findings = report.reportable
    if not findings:
        return ""
    cards = "".join(_card(finding) for finding in findings)
    return f'<section class="findings"><h2>Findings</h2>{cards}</section>'


def _card(finding: Finding) -> str:
    colour = SEVERITY_COLOURS[finding.severity]

    rows = "".join(
        f"<tr><th><code>{escape(change.path)}</code></th>"
        f"<td>{_value(change.before)}</td>"
        f"<td>{_value(change.after)}</td></tr>"
        for change in finding.changes[:CHANGE_LIMIT]
    )
    extra = len(finding.changes) - CHANGE_LIMIT
    if extra > 0:
        rows += (
            f'<tr><td colspan="3" class="more">and {extra} more '
            f"attribute{'s' if extra != 1 else ''}</td></tr>"
        )

    table = (
        f"""
  <table class="changes">
    <thead><tr><th>Attribute</th><th>In your code</th><th>Actually</th></tr></thead>
    <tbody>{rows}</tbody>
  </table>"""
        if rows
        else ""
    )

    cost = ""
    if finding.cost:
        cost = f"""
  <p class="cost"><strong>About ${finding.cost.monthly_usd:,.2f}/month different.</strong>
  <span class="basis">{escape(finding.cost.basis)}</span></p>"""

    return f"""
<article class="finding" style="--severity:{colour}">
  <div class="finding-head">
    <span class="badge" style="background:{colour}">{escape(finding.severity.label)}</span>
    <code class="address">{escape(finding.address)}</code>
  </div>
  <p class="meta">{escape(finding.stack)} &middot; {escape(finding.resource_type)}
  &middot; {escape(finding.kind.label)}</p>
  {table}
  <p class="why">{escape(finding.severity_reason)}
  <span class="rule">rule <code>{escape(finding.severity_rule)}</code></span></p>
  <p class="who"><span class="k">Who changed it</span> {_who(finding)}</p>
  {cost}
  <p class="do"><span class="k">Recommendation</span>
  <strong>{escape(finding.recommendation.label)}</strong> &mdash;
  {escape(finding.recommendation_reason)}</p>
</article>
"""


def _who(finding: Finding) -> str:
    """Attribution, or a plain statement that we do not know.

    Never a name without the event ID beside it. A reader who wants to check
    can paste that into the CloudTrail console and see what we saw.
    """
    attribution = finding.attribution
    if not attribution.known or attribution.event is None:
        return (
            f'<span class="unknown">Unknown</span> '
            f'<span class="basis">{escape(reason(attribution.reason))}</span>'
        )
    event = attribution.event
    when = event.event_time.strftime("%Y-%m-%d %H:%M UTC")
    return (
        f"<strong>{escape(attribution.actor or '')}</strong> "
        f"&middot; <code>{escape(event.event_name)}</code> &middot; {escape(when)} "
        f'<span class="basis">{escape(attribution.confidence.label)} confidence '
        f"&middot; event <code>{escape(event.event_id)}</code> "
        f"&middot; {escape(event.region)}</span>"
    )


def _value(value: object) -> str:
    if value is None:
        return '<span class="none">(none)</span>'
    return f"<code>{escape(str(value))}</code>"


def _footer(report: Report) -> str:
    notes = ""
    if report.attribution_note:
        notes += f"<p>{escape(report.attribution_note)}</p>"
    for note in report.notes:
        notes += f"<p>{escape(note)}</p>"

    return f"""
<footer>
  {notes}
  <p><strong>Crosswind is read-only.</strong> It ran
  <code>terraform plan -refresh-only</code> against your state, read CloudTrail, and
  changed nothing. Every recommendation is for a person to carry out.</p>
  <p class="limits">Drift is only detected in resources Terraform already manages.
  Attribution depends on CloudTrail, which keeps 90 days of management events and
  does not record data-plane changes &mdash; so &ldquo;unknown&rdquo; means
  &ldquo;no evidence&rdquo;, never &ldquo;nobody&rdquo;.</p>
  <p class="brand">Generated by <strong>Crosswind</strong>, an open-source tool from
  <a href="https://jetonecloud.com">Jet1</a>.</p>
</footer>
"""


#: Inline, because the file has to work with no network. Written out rather
#: than minified so that someone who wants to check what this page does can
#: read it.
_CSS = f"""
:root {{
  --ink: {INK}; --dim: {DIM}; --rule: {RULE};
  --accent: {ACCENT}; --wash: {WASH}; --paper: {PAPER}; --good: {GOOD};
}}
* {{ box-sizing: border-box; }}
body {{
  margin: 0; padding: 2rem 1rem 4rem;
  font-family: Helvetica, Arial, -apple-system, BlinkMacSystemFont, sans-serif;
  font-size: 16px; line-height: 1.55; color: var(--ink); background: var(--paper);
  -webkit-text-size-adjust: 100%;
}}
main {{ max-width: 56rem; margin: 0 auto; }}
code, pre {{
  font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
  font-size: 0.875em;
}}
h1 {{ font-size: 1.75rem; line-height: 1.25; margin: 0 0 .5rem; }}
h2 {{
  font-size: 1.125rem; color: var(--accent); margin: 2.5rem 0 1rem;
  padding-bottom: .4rem; border-bottom: 1.5px solid var(--accent);
}}
p {{ margin: 0 0 .75rem; }}
a {{ color: var(--accent); }}

header {{ border-top: 3px solid var(--accent); padding-top: 1.25rem; }}
.eyebrow {{
  text-transform: uppercase; letter-spacing: .09em; font-size: .7rem;
  font-weight: bold; color: var(--accent); margin: 0 0 .35rem;
}}
.lede {{ color: var(--dim); max-width: 44rem; }}

.facts {{
  display: flex; flex-wrap: wrap; gap: 0 2.5rem;
  margin: 1.25rem 0 0; padding: .9rem 0 0; border-top: 1px solid var(--rule);
}}
.facts div {{ margin: 0 0 .5rem; }}
.facts dt {{
  font-size: .68rem; text-transform: uppercase; letter-spacing: .07em;
  color: var(--dim); font-weight: bold;
}}
.facts dd {{ margin: 0; font-size: .9rem; }}

.summary {{ margin-top: 1.75rem; }}
.tiles {{ display: flex; flex-wrap: wrap; gap: .75rem; }}
.tile {{
  flex: 1 1 7rem; background: var(--wash); border: 1px solid var(--rule);
  border-radius: 3px; padding: .85rem 1rem; text-align: center;
}}
.tile.muted {{ background: transparent; opacity: .5; }}
.tile .count {{ display: block; font-size: 1.9rem; font-weight: bold; line-height: 1.1; }}
.tile .label {{
  display: block; font-size: .68rem; text-transform: uppercase;
  letter-spacing: .07em; color: var(--dim); font-weight: bold;
}}
.stacks {{ margin-top: .9rem; font-size: .9rem; color: var(--dim); }}
.clean {{
  background: var(--wash); border-left: 3px solid var(--good);
  padding: .9rem 1rem; font-size: 1.05rem;
}}
.bad {{ color: {SEVERITY_COLOURS[Severity.CRITICAL]}; }}

.failures {{ margin-top: 1rem; }}
.failures h2 {{ color: {SEVERITY_COLOURS[Severity.CRITICAL]};
  border-bottom-color: {SEVERITY_COLOURS[Severity.CRITICAL]}; }}
.warn {{
  background: #fdf3f2; border-left: 3px solid {SEVERITY_COLOURS[Severity.CRITICAL]};
  padding: .75rem 1rem; font-weight: bold;
}}
details {{ border: 1px solid var(--rule); border-radius: 3px; margin: .5rem 0; }}
summary {{ cursor: pointer; padding: .6rem .9rem; font-weight: bold; }}
details pre {{
  margin: 0; padding: .9rem; border-top: 1px solid var(--rule);
  background: #fafbfb; overflow-x: auto; white-space: pre-wrap;
  word-break: break-word; font-size: .8rem;
}}

.finding {{
  border: 1px solid var(--rule); border-left: 4px solid var(--severity);
  border-radius: 3px; padding: 1.1rem 1.25rem; margin-bottom: 1rem;
  break-inside: avoid;
}}
.finding-head {{ display: flex; align-items: center; gap: .6rem; flex-wrap: wrap; }}
.badge {{
  color: #fff; font-size: .62rem; font-weight: bold; text-transform: uppercase;
  letter-spacing: .08em; padding: .2rem .5rem; border-radius: 2px;
}}
.address {{ font-size: 1rem; font-weight: bold; word-break: break-all; }}
.meta {{ font-size: .78rem; color: var(--dim); margin: .3rem 0 .9rem; }}

table.changes {{
  width: 100%; border-collapse: collapse; margin: 0 0 .9rem;
  font-size: .82rem; display: block; overflow-x: auto;
}}
table.changes thead th {{
  text-align: left; font-size: .64rem; text-transform: uppercase;
  letter-spacing: .07em; color: var(--dim); padding: .35rem .5rem;
  border-bottom: 1px solid var(--rule); white-space: nowrap;
}}
table.changes tbody th {{
  text-align: left; font-weight: normal; padding: .4rem .5rem;
  border-bottom: 1px solid #eef0f2; vertical-align: top;
}}
table.changes td {{
  padding: .4rem .5rem; border-bottom: 1px solid #eef0f2;
  vertical-align: top; word-break: break-word;
}}
table.changes td.more {{ color: var(--dim); font-style: italic; }}
.none {{ color: var(--dim); font-style: italic; }}

.why {{ font-size: .92rem; }}
.rule, .basis {{ color: var(--dim); font-size: .78rem; }}
.k {{
  display: inline-block; min-width: 8.5rem; font-size: .64rem;
  text-transform: uppercase; letter-spacing: .07em; color: var(--dim);
  font-weight: bold;
}}
.who, .do, .cost {{ font-size: .9rem; margin-bottom: .4rem; }}
.unknown {{ color: var(--dim); font-style: italic; }}
.cost {{ background: var(--wash); padding: .6rem .8rem; border-radius: 3px; }}

footer {{
  margin-top: 3rem; padding-top: 1.1rem; border-top: 1px solid var(--rule);
  font-size: .82rem; color: var(--dim);
}}
footer .brand {{ margin-top: 1rem; }}

@media print {{
  body {{ padding: 0; font-size: 11pt; }}
  details {{ display: block; }}
  details > summary {{ list-style: none; }}
  .finding {{ page-break-inside: avoid; }}
  a[href]:after {{ content: " (" attr(href) ")"; font-size: .8em; }}
}}
"""
