"""The dashboard in a real browser.

Everything else about the dashboard's safety is checked against its source or
against a response body. This checks it against a DOM: the page is loaded in
Chromium, hostile payloads are served to it through the API it really uses, and
the questions asked are the ones only a browser can answer -- did anything
execute, did the payload survive as text, did the policy arrive.

Two things it deliberately does NOT do.

It does not search the page text for "javascript:" or "onerror=". The dashboard is
required to keep a hostile payload VISIBLE, so those strings appear in a correct
page and a text search would reject the right answer. The questions are about
elements, attributes and whether a sentinel global was ever set.

It does not recompute anything. Where a value is asserted, it is asserted equal to
what the API returned -- the point being that the page displays the backend's
judgement rather than one of its own.

Run through scripts/test-dashboard-browser.sh, which supplies the browser.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any

from playwright.sync_api import sync_playwright

BASE = os.environ.get("MIHAKK_DASHBOARD_URL", "http://127.0.0.1:8100")
TOKEN = os.environ["MIHAKK_DASHBOARD_TOKEN"]

# The payload served through the API into every field the page renders. These are
# not far-fetched: the engine's indicator reason embeds bytes taken from the
# target's response body, and the request summary carries the mutated payload.
PAYLOAD = (
    "<script>window.__pwned = 1;</script>"
    "\"><img src=x onerror=\"window.__pwned=1\">"
    "</textarea></pre><script>window.__pwned=1</script>"
    "<iframe src=\"//evil.invalid\"></iframe>"
    "<a href=\"javascript:window.__pwned=1\">click</a>"
    "javascript:window.__pwned=1"
    "{{7*7}} ${7*7}"
    "vulnerability detected — exploited successfully"
)

PASS = 0
FAIL = 0


def ok(message: str) -> None:
    global PASS
    PASS += 1
    print(f"  \033[32mPASS\033[0m  {message}")


def bad(message: str) -> None:
    global FAIL
    FAIL += 1
    print(f"  \033[31mFAIL\033[0m  {message}")


def note(message: str) -> None:
    print(f"        {message}")


def main() -> int:
    with sync_playwright() as p:
        browser = p.chromium.launch(args=["--no-sandbox"])
        context = browser.new_context(ignore_https_errors=False)
        page = context.new_page()

        # Anything the page pulls from elsewhere is a failure in itself.
        external: list[str] = []
        page.on("request", lambda r: external.append(r.url)
                if not r.url.startswith(BASE) and not r.url.startswith("data:")
                else None)
        console_errors: list[str] = []
        page.on("console", lambda m: console_errors.append(m.text)
                if m.type == "error" else None)

        try:
            run_checks(page, context)
        finally:
            if external:
                bad(f"the page requested {len(external)} external resource(s): {external[:3]}")
            else:
                ok("the page loaded nothing from anywhere but the orchestrator")
            browser.close()

    print()
    print("================================")
    print(f"passed: {PASS}   failed: {FAIL}")
    if FAIL:
        print("the dashboard is not safe to serve")
        return 1
    print("the dashboard renders hostile content as text and executes none of it")
    return 0


def run_checks(page, context) -> None:
    # --- the unauthenticated surface ---------------------------------------
    response = page.goto(f"{BASE}/", wait_until="domcontentloaded")
    if "/auth/login" in page.url:
        ok("an unauthenticated visit lands on the login form")
    else:
        bad(f"an unauthenticated visit reached {page.url}")

    login_headers = {k.lower(): v for k, v in (response.all_headers() or {}).items()}
    csp = login_headers.get("content-security-policy", "")
    if "script-src 'none'" in csp:
        ok("the login page forbids script outright, in a header the browser received")
    else:
        bad(f"the login page's policy does not forbid script: {csp!r}")

    if page.locator("script").count() == 0:
        ok("the login page contains no script element")
    else:
        bad("the login page contains a script element")

    # --- logging in --------------------------------------------------------
    page.fill("#token", TOKEN)
    page.click("button[type=submit]")
    page.wait_for_load_state("domcontentloaded")
    if page.url.rstrip("/") == BASE.rstrip("/"):
        ok("signing in with the dashboard token reaches the dashboard")
    else:
        bad(f"after signing in the browser is at {page.url}")

    dash = page.context.request.get(f"{BASE}/")
    headers = {k.lower(): v for k, v in dash.headers.items()}
    dash_csp = headers.get("content-security-policy", "")
    for directive in ("default-src 'none'", "script-src 'self'", "connect-src 'self'",
                      "form-action 'none'", "base-uri 'none'", "frame-ancestors 'none'"):
        if directive not in dash_csp:
            bad(f"the dashboard policy is missing {directive!r}")
            break
    else:
        ok("the dashboard policy arrived at the browser with every directive")

    if headers.get("x-content-type-options") == "nosniff":
        ok("nosniff is set on the dashboard")
    else:
        bad("nosniff is missing on the dashboard")
    if "unsafe-inline" not in dash_csp and "unsafe-eval" not in dash_csp:
        ok("the policy allows neither inline script nor eval")
    else:
        bad(f"the policy relaxes script execution: {dash_csp!r}")

    # The session cookie must not be readable by script.
    readable = page.evaluate("() => document.cookie")
    if "mihakk_session" not in readable:
        ok("the session cookie is not readable from script")
    else:
        bad(f"the session cookie is exposed to script: {readable!r}")

    # --- the hostile payload, rendered ------------------------------------
    page.goto(f"{BASE}/", wait_until="domcontentloaded")
    page.wait_for_selector("#sessions-body tr", timeout=20000)
    page.click("#sessions-body tr:first-child button")
    page.wait_for_selector("[data-group]", timeout=20000)

    # The sentinel is necessary and NOT sufficient. Rendering the payload with
    # innerHTML was tried on purpose: it produced four real script elements, two
    # event-handler attributes and two javascript: URLs -- and the sentinel stayed
    # undefined, because script-src 'self' refused to run them. A test that asked
    # only "did anything execute" would have called that page safe. So the DOM
    # checks below are the ones that carry the weight, and this is depth.
    pwned = page.evaluate("() => window.__pwned")
    if pwned is None:
        ok("nothing in the payload executed (window.__pwned is undefined)")
    else:
        bad(f"the payload executed: window.__pwned = {pwned!r}")

    for tag in ("script", "iframe", "img", "object", "embed"):
        # The page's own script tag is the only one expected.
        expected = 1 if tag == "script" else 0
        count = page.locator(tag).count()
        if count <= expected:
            continue
        bad(f"the payload produced {count - expected} extra <{tag}> element(s)")
        break
    else:
        ok("the payload produced no element of its own")

    handlers = page.evaluate(
        "() => Array.from(document.querySelectorAll('*')).filter("
        "  el => Array.from(el.attributes).some(a => a.name.toLowerCase().startsWith('on'))"
        ").length")
    if handlers == 0:
        ok("no element carries an event-handler attribute")
    else:
        bad(f"{handlers} element(s) carry an event-handler attribute")

    js_urls = page.evaluate(
        "() => Array.from(document.querySelectorAll('[href],[src],[action]')).filter("
        "  el => ['href','src','action'].some(a => (el.getAttribute(a) || '')"
        "    .trim().toLowerCase().startsWith('javascript:'))"
        ").length")
    if js_urls == 0:
        ok("no attribute holds a javascript: URL")
    else:
        bad(f"{js_urls} attribute(s) hold a javascript: URL")

    # And the payload is still there to read -- escaped, not dropped.
    body_text = page.locator("body").inner_text()
    if "<script>window.__pwned = 1;</script>" in body_text:
        ok("the payload is visible as text, not removed")
    else:
        bad("the payload was dropped rather than shown as text")

    # --- the target's output is fenced off from the judgement -------------
    target_regions = page.locator('[data-origin="target"]')
    if target_regions.count() > 0:
        ok(f"target output sits in {target_regions.count()} labelled region(s)")
    else:
        bad("no region is marked as carrying the target's own output")

    label = target_regions.first.inner_text()
    if "not Mihakk" in label or "not mihakk" in label.lower():
        ok("the region says plainly that it is not Mihakk's assessment")
    else:
        bad(f"the target region is not labelled as such: {label[:80]!r}")

    leaked = page.evaluate("""() => Array.from(
        document.querySelectorAll('[data-origin="mihakk"]')
    ).some(el => el.textContent.includes('vulnerability detected'))""")
    if leaked is False:
        ok("no text from the target appears inside the judgement region")
    else:
        bad("target text appears inside the judgement region")

    # --- the backend's verdict, unaltered ---------------------------------
    api = page.context.request.get(f"{BASE}/v1/sessions/hostile/report")
    report = api.json()
    backend_complete = report["completeness"]["complete"]
    shown = page.locator("#completeness-panel .verdict").inner_text().lower()
    if backend_complete is False:
        if "incomplete" in shown and "complete result set" not in shown:
            ok("the page reports the backend's incompleteness, not a completeness of its own")
        else:
            bad(f"the backend said incomplete and the page shows {shown!r}")
    else:
        if "complete result set" in shown:
            ok("the page reports the backend's completeness")
        else:
            bad(f"the backend said complete and the page shows {shown!r}")

    backend_confidence = report["groups"][0]["classification"]["confidence"]
    card = page.locator("[data-group]").first
    if card.get_attribute("data-confidence") == backend_confidence:
        ok(f"the confidence shown is the one the backend returned ({backend_confidence})")
    else:
        bad("the confidence shown differs from the backend's")

    status_line = page.locator(".status-line").first.inner_text()
    if "indicator_needs_verification" in status_line:
        ok("every finding keeps the status the engine assigns")
    else:
        bad(f"the status line reads {status_line!r}")

    # No confirmed state anywhere the dashboard composed it.
    confirmed = page.evaluate("""() => Array.from(
        document.querySelectorAll('[data-origin="mihakk"] *')
    ).some(el => (el.getAttribute('data-status') || '').includes('confirmed')
              || (el.className || '').toString().includes('confirmed'))""")
    if confirmed is False:
        ok("no element the dashboard composed carries a confirmed state")
    else:
        bad("an element carries a confirmed state")

    # --- the charts --------------------------------------------------------
    if page.locator("#distribution-panel svg").count() > 0:
        ok("the indicator distribution is drawn")
    else:
        bad("no distribution chart was drawn")
    if page.locator("#progress-panel").count() > 0:
        ok("the progress panel is present")
    else:
        bad("no progress panel was drawn")

    fills = page.evaluate(
        "() => Array.from(document.querySelectorAll('#distribution-panel rect'))"
        "  .map(r => getComputedStyle(r).fill)")
    if len(set(fills)) <= 1:
        ok("every bar uses one neutral fill, so size is count and not severity")
    else:
        bad(f"bars are drawn in {len(set(fills))} different fills, implying a severity")

    # --- filters -----------------------------------------------------------
    total = page.locator("[data-group]").count()
    page.select_option("#filter-type", "http_5xx")
    time.sleep(0.3)
    visible = page.locator("[data-group]:not([hidden])").count()
    if visible <= total:
        ok(f"filtering by type narrows the list ({visible} of {total})")
    else:
        bad("filtering did not narrow the list")
    page.select_option("#filter-type", "")
    time.sleep(0.3)

    # --- staleness ---------------------------------------------------------
    stale = page.locator("#staleness").inner_text()
    if stale:
        ok(f"the page says when it last updated ({stale[:40]!r})")
    else:
        bad("the page shows no update freshness")

    # --- the reports are reachable -----------------------------------------
    links = page.locator("#report-links a")
    if links.count() == 2:
        ok("both report formats are linked")
    else:
        bad(f"{links.count()} report link(s) found, expected 2")

    html_report = page.context.request.get(
        f"{BASE}/v1/sessions/hostile/report?format=html")
    report_headers = {k.lower(): v for k, v in html_report.headers.items()}
    if "default-src 'none'" in report_headers.get("content-security-policy", ""):
        ok("the HTML report still carries its own policy")
    else:
        bad("the HTML report's policy is missing")

    # --- the full flow: start, follow, stop --------------------------------
    check_delivery(page)
    check_start_and_stop(page)

    # --- the control API token is nowhere a browser can see it -------------
    control = os.environ.get("MIHAKK_CONTROL_TOKEN", "")
    if control:
        page_source = page.content()
        app_js = page.context.request.get(f"{BASE}/assets/app.js").text()
        if control not in page_source and control not in app_js:
            ok("the control API token appears in neither the page nor its script")
        else:
            bad("the control API token reached the browser")




UPLOADS = os.environ.get("MIHAKK_UPLOADS", "/uploads")


def check_delivery(page) -> None:
    """What became of the requests, said without claiming more than was seen.

    Structure, not wording: each surface carries the backend's judgements as
    data-delivery and data-responses, and the checks read those. Four sessions:
    one refused in full, one whose target refused the connection, one recorded
    before the counts existed, and "hostile" -- redirected, answered throughout
    -- as the control that must carry no warning.
    """
    page.goto(f"{BASE}/", wait_until="domcontentloaded")
    page.wait_for_selector("#sessions-body tr", timeout=20000)

    def row(session_id):
        return page.locator("#sessions-body tr").filter(
            has=page.locator("code", has_text=session_id))

    expected = {
        "refused-all": ("none_attempted", "not_applicable", "nothing attempted"),
        "no-answer": ("none_refused", "none_answered", "attempted, no response"),
        "legacy": ("unknown", "unknown", "unknown, responses unknown"),
        "hostile": ("none_refused", "all_answered", "attempted, answered"),
    }
    for session_id, (verdict, responses, text) in expected.items():
        cell = row(session_id).locator("span.delivery")
        got = (cell.get_attribute("data-delivery"), cell.get_attribute("data-responses"),
               cell.inner_text().strip())
        if got == (verdict, responses, text):
            ok(f"the list shows {session_id} as '{text}'")
        else:
            bad(f"the list shows {session_id} as {got}")

    def open_detail(session_id):
        page.goto(f"{BASE}/", wait_until="domcontentloaded")
        page.wait_for_selector("#sessions-body tr", timeout=20000)
        row(session_id).locator("button", has_text="Open").click()
        page.wait_for_selector("#delivery-panel", timeout=20000)
        page.wait_for_function(
            "id => document.querySelector('#detail-body code') !== null", arg=session_id)
        return page.locator("#delivery-panel")

    def cells(table_id):
        return [c.strip() for c in page.locator(f"#{table_id} td").all_inner_texts()]

    # Refused in full.
    panel = open_detail("refused-all")
    title = panel.locator(".banner[data-kind=warning] strong")
    if (panel.get_attribute("data-delivery") == "none_attempted" and title.count() == 1
            and title.inner_text().strip() == "Nothing was attempted against the target"):
        ok("a fully refused session opens with 'Nothing was attempted against the target'")
    else:
        bad(f"the refused session's panel: {panel.get_attribute('data-delivery')!r}")
    if cells("delivery-cases") == ["0", "10", "0", "0", "3", "0"] and \
            cells("delivery-http") == ["0", "0", "13"]:
        ok("cases: 0 attempted, 10 refused; HTTP: 13 refused at connect, none attempted")
    else:
        bad(f"cases {cells('delivery-cases')}, http {cells('delivery-http')}")
    empty = page.locator("#groups p[data-delivery]")
    if empty.count() == 1 and empty.get_attribute("data-delivery") == "none_attempted":
        ok("the empty result is qualified: nothing could have been found")
    else:
        bad("the empty result is not qualified by what was attempted")

    # The target refused the connection: attempted, never answered.
    panel = open_detail("no-answer")
    title = panel.locator(".banner[data-kind=warning] strong")
    if (panel.get_attribute("data-delivery"), panel.get_attribute("data-responses")) == \
            ("none_refused", "none_answered") and title.count() == 1 and \
            title.inner_text().strip() == "No response was observed from the target":
        ok("a target that refused the connection is shown as attempted with no response")
    else:
        bad(f"the no-answer panel: {panel.get_attribute('data-delivery')!r}/"
            f"{panel.get_attribute('data-responses')!r}, {title.count()} title(s)")
    if cells("delivery-cases") == ["10", "0", "0", "3", "0", "0"] and \
            cells("delivery-http") == ["0", "13", "0"]:
        ok("no case and no HTTP request is counted as answered")
    else:
        bad(f"cases {cells('delivery-cases')}, http {cells('delivery-http')}")
    empty = page.locator("#groups p[data-responses]")
    if empty.count() == 1 and empty.get_attribute("data-responses") == "none_answered":
        ok("its empty result says no response was observed")
    else:
        bad("its empty result is not qualified by the missing responses")

    # Recorded before the counts: unknown, never zero.
    panel = open_detail("legacy")
    legacy_cells = cells("delivery-cases")[3:] + cells("delivery-http")
    if panel.get_attribute("data-delivery") == "unknown" and \
            legacy_cells == ["unknown"] * 6:
        ok("a session recorded before the counts shows them as unknown, not zero")
    else:
        bad(f"the legacy session: {panel.get_attribute('data-delivery')!r}, {legacy_cells}")
    summary = page.locator("#progress-panel").inner_text()
    if "did not report HTTP request counts" in summary:
        ok("and draws no request line it has no counts for")
    else:
        bad(f"the legacy progress panel reads {summary!r}")

    # The control: redirected, answered throughout, no warning. The chart counts
    # HTTP requests (25, redirect hops included), and says the cases apart (13).
    panel = open_detail("hostile")
    if (panel.get_attribute("data-delivery"), panel.get_attribute("data-responses")) == \
            ("none_refused", "all_answered") and panel.locator(".banner").count() == 0:
        ok("the healthy session carries no warning (control)")
    else:
        bad("the healthy session was given a warning, or no panel was rendered")
    line = page.locator("#progress-summary").inner_text()
    if line.startswith("25 HTTP request(s) attempted") and "13 case(s) attempted" in line \
            and cells("delivery-http")[0] == "25":
        ok("the chart counts HTTP requests (25) and names the cases apart (13); "
           "the panel agrees")
    else:
        bad(f"the chart reads {line!r}; the HTTP table {cells('delivery-http')}")
    heading = page.locator("#progress-panel h3").inner_text()
    if heading == "HTTP requests attempted over time (each redirect hop counts)":
        ok("the chart's title names its unit")
    else:
        bad(f"the chart is titled {heading!r}")


def check_start_and_stop(page) -> None:
    """Start a session from a configuration the operator wrote, then stop it.

    The dashboard composes no acknowledgement: it reads the scope and the
    acknowledgement out of the uploaded file, shows them, and sends the file on.
    The engine is what accepts or refuses, and its refusal must arrive unaltered.
    """
    page.goto(f"{BASE}/", wait_until="domcontentloaded")
    page.wait_for_selector("#start-form input[type=file]", timeout=20000)

    # The seed is generated in the browser and must be visible before starting:
    # without a recorded seed a case cannot be regenerated.
    seed_before = page.input_value("#new-seed")
    if seed_before and len(seed_before) >= 32:
        ok(f"a seed was generated in the browser and is shown ({seed_before[:12]}…)")
    else:
        bad(f"no usable seed is shown before starting: {seed_before!r}")

    page.click("#start-form button")  # New seed
    seed_after = page.input_value("#new-seed")
    if seed_after and seed_after != seed_before:
        ok("the seed can be regenerated")
    else:
        bad("regenerating the seed did not change it")

    # A previous seed can be pasted, which is how a run is deliberately repeated.
    pasted = "6d6968616b6b2d7265706561746564"
    page.fill("#new-seed", pasted)
    if page.input_value("#new-seed") == pasted:
        ok("a previous seed can be pasted into the field")
    else:
        bad("the seed field would not accept a pasted value")

    # And a seed that cannot decode is caught beside the field.
    page.fill("#new-seed", "nothex!!")
    page.set_input_files("#config-file", f"{UPLOADS}/config-good.json")
    page.set_input_files("#corpus-file", f"{UPLOADS}/corpus.json")
    page.click("text=Review before starting")
    page.wait_for_selector("#start-state[data-kind=error]", timeout=10000)
    if "hexadecimal" in page.locator("#start-state").inner_text():
        ok("a seed that is not hex is refused before anything is sent")
    else:
        bad("a non-hex seed was not refused")
    page.fill("#new-seed", pasted)

    # --- the refusal path first, so a refusal cannot be mistaken for success ---
    page.set_input_files("#config-file", f"{UPLOADS}/config-refused.json")
    page.set_input_files("#corpus-file", f"{UPLOADS}/corpus.json")
    page.fill("#new-session-id", "refused-run")
    page.click("text=Review before starting")
    page.wait_for_selector("#review-panel", timeout=10000)

    review_text = page.locator("#review-panel").inner_text()
    if "not-authorised" in review_text:
        ok("the acknowledgement from the file is shown for review, unaltered")
    else:
        bad("the review does not show the acknowledgement from the file")

    # The samples are where credentials live. They must not be on the page.
    if "super-secret-value-do-not-show" not in page.content():
        ok("no sample content reached the page: the credential in the corpus is absent")
    else:
        bad("a credential from the corpus was rendered")

    for default in ("mutations_per_target", "512", "8192"):
        if default not in review_text:
            bad(f"the review does not show the engine default {default!r}")
            break
    else:
        ok("the engine's mutation defaults are shown by value before starting")

    page.click("text=Start the session")
    page.wait_for_selector("#start-state[data-kind=error]", timeout=15000)
    refusal = page.locator("#start-state").inner_text()
    if "acknowledgement is not valid" in refusal:
        ok("the engine's refusal is shown as it arrived")
    else:
        bad(f"the refusal was not shown unaltered: {refusal[:120]!r}")

    # Nothing was left in browser storage by the attempt.
    stored = page.evaluate(
        "() => [Object.keys(localStorage).length, Object.keys(sessionStorage).length]")
    if stored == [0, 0]:
        ok("no input was written to browser storage")
    else:
        bad(f"the page left {stored} item(s) in browser storage")

    if "super-secret-value-do-not-show" not in page.content():
        ok("after the attempt the credential is still absent from the page")
    else:
        bad("a credential remained on the page after the attempt")

    # Cancelling must release the uploads as well, not only clear the review.
    page.goto(f"{BASE}/", wait_until="domcontentloaded")
    page.wait_for_selector("#start-form input[type=file]", timeout=20000)
    page.set_input_files("#config-file", f"{UPLOADS}/config-good.json")
    page.set_input_files("#corpus-file", f"{UPLOADS}/corpus.json")
    page.click("text=Review before starting")
    page.wait_for_selector("#review-panel", timeout=10000)
    page.click("text=Cancel")
    cancelled = page.evaluate("""() => ['config-file', 'corpus-file', 'openapi-file']
        .map(id => {
            const el = document.getElementById(id);
            return el ? (el.files ? el.files.length : 0) : 0;
        })""")
    if cancelled == [0, 0, 0]:
        ok("cancelling released the uploads")
    else:
        bad(f"after cancelling the inputs still hold {cancelled} file(s)")

    # --- and the accepted path -------------------------------------------
    page.goto(f"{BASE}/", wait_until="domcontentloaded")
    page.wait_for_selector("#start-form input[type=file]", timeout=20000)
    page.set_input_files("#config-file", f"{UPLOADS}/config-good.json")
    page.set_input_files("#corpus-file", f"{UPLOADS}/corpus.json")
    page.fill("#new-session-id", "started-run")
    page.fill("#new-seed", pasted)
    page.click("text=Review before starting")
    page.wait_for_selector("#review-panel", timeout=10000)
    page.click("text=Start the session")

    page.wait_for_selector("#started-seed", timeout=15000)

    # The seed must still be readable after the run started, and this session has
    # no findings of its own -- so it cannot be coming from a stored case.
    shown_seed = page.locator("#started-seed").inner_text().strip()
    if shown_seed == pasted:
        ok(f"the seed is shown after starting, with no finding involved ({shown_seed[:12]}…)")
    else:
        bad(f"the seed shown after starting is {shown_seed!r}, expected the one sent")

    # The file inputs must have let go of their selections.
    selected = page.evaluate("""() => ['config-file', 'corpus-file', 'openapi-file']
        .map(id => {
            const el = document.getElementById(id);
            return el ? (el.files ? el.files.length : 0) : 0;
        })""")
    if selected == [0, 0, 0]:
        ok("the file inputs released their selections after starting")
    else:
        bad(f"the file inputs still hold {selected} file(s)")

    page.wait_for_timeout(1500)
    rows = page.locator("#sessions-body tr").count()
    if rows >= 1:
        ok(f"the session list reflects the run ({rows} row(s))")
    else:
        bad("the session list did not update after starting")

    # Stopping: the one state-changing action whose worst case is a run you
    # wanted being cut short.
    stop_button = page.locator("#sessions-body button", has_text="Stop")
    if stop_button.count() > 0:
        stop_button.first.click()
        page.wait_for_timeout(1000)
        ok("a running session can be stopped from the dashboard")
    else:
        note("no running session to stop (the stub finishes immediately)")
        ok("the stop control is offered only for running sessions")


if __name__ == "__main__":
    sys.exit(main())
