#!/usr/bin/env python3
# Generate docs/api.html from each package's pkg.generated.mbti and the /// comments in its
# sources. Deterministic: no timestamps, sorted order, LF endings. CI re-runs this and asserts
# `git diff --exit-code docs/api.html` is empty.
import html
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
MBTI = "pkg.generated.mbti"
OUT = ROOT / "docs" / "api.html"

# The order the site presents them in: the contract, the four adapters that implement it, the
# two transports underneath, the pool, and the front door.
PACKAGES = [
    ("spec", "moonnet/spec", "The contract: one exchange, whatever carries it."),
    ("adapt/h1", "moonnet/adapt/h1", "HTTP/1.1, RFC 9112."),
    ("adapt/h2", "moonnet/adapt/h2", "HTTP/2, RFC 9113."),
    ("adapt/h3", "moonnet/adapt/h3", "HTTP/3, RFC 9114, over QUIC."),
    ("adapt/ws", "moonnet/adapt/ws", "WebSocket, RFC 6455."),
    ("tcp", "moonnet/tcp", "TCP, and TLS over it: connections, the listener, the dialler."),
    ("udp", "moonnet/udp", "The datagram socket, and the client end of a QUIC connection."),
    ("pool", "moonnet/pool", "Connections kept by host, port and ALPN."),
    ("", "moonnet", "The front door: one import for the connection, the datagram socket and the contract."),
]

# Methods a derive produces; they are not the public surface to document.
DERIVED = {"equal", "not_equal", "to_repr", "output", "compare", "hash"}


def sources_of(directory):
    return sorted(
        p
        for p in directory.glob("*.mbt")
        if not p.name.endswith(("_test.mbt", "_wbtest.mbt"))
    )


def parse_comments(files):
    """Map `Type`, `Type::method` and `Type::Variant` to the comment above it."""
    docs = {}
    for path in files:
        buf = []
        owner = None  # the type or trait whose body we are inside
        depth = 0
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.strip()
            if line.startswith("///"):
                buf.append(re.sub(r"^///\|?\s?", "", line))
                continue
            if not line or line.startswith("#"):
                continue
            key = None
            variant = None
            if owner is not None:
                m = re.match(r"(?:async\s+)?fn\s+(\w+)\s*\(", line)
                if m:
                    key = f"{owner}::{m.group(1)}"
                else:
                    m = re.match(r"([A-Z][A-Za-z0-9_]*)\s*(?:\(|\{|$)", line)
                    if m:
                        variant = f"{owner}::{m.group(1)}"
                if line.startswith("}"):
                    depth -= 1
                    if depth <= 0:
                        owner = None
                        depth = 0
            else:
                m = re.match(r"pub fn (\w+)::(\w+)", line)
                if m:
                    key = f"{m.group(1)}::{m.group(2)}"
                else:
                    m = re.match(r"pub fn (\w+)\s*\(", line)
                    if m:
                        key = m.group(1)
                    else:
                        m = re.match(r"pub let (\w+)\s*:", line)
                        if m:
                            key = m.group(1)
                        else:
                            m = re.match(
                                r"(?:pub(?:\([a-z]+\))?\s+)?(?:struct|enum|trait)\s+(\w+)\s*\{",
                                line,
                            )
                            if m:
                                owner = m.group(1)
                                depth = 1
                                key = m.group(1)
                            else:
                                m = re.match(r"pub\(all\)\s+suberror\s+(\w+)\s*\{", line)
                                if m:
                                    owner = m.group(1)
                                    depth = 1
                                    key = m.group(1)
                                else:
                                    m = re.match(r"type\s+(\w+)\s*$", line)
                                    if m:
                                        key = m.group(1)
            if key and buf:
                docs[key] = "\n".join(buf).strip()
            if variant and buf:
                docs[variant] = "\n".join(buf).strip()
            buf = []
    return docs


def parse_mbti(path):
    values, types, traits, impls = [], [], [], []
    section = "values"
    cur = None
    in_block = False
    for raw in path.read_text(encoding="utf-8").splitlines():
        s = raw.strip()
        if s.startswith("// Values"):
            section = "values"
            continue
        if s.startswith("// Errors"):
            section = "errors"
            continue
        if s.startswith("// Types"):
            section = "types"
            continue
        if s.startswith("// Type aliases"):
            section = "aliases"
            continue
        if s.startswith("// Traits"):
            section = "traits"
            continue
        if not s or s.startswith("//"):
            continue
        if in_block:
            if s == "}":
                in_block = False
                continue
            if s:
                cur["members"].append(s)
            continue
        m = re.match(r"pub(?:\(all\))?\s+(struct|enum|suberror)\s+(\w+)\s*\{", s)
        if m:
            kind = "suberror" if m.group(1) == "suberror" else m.group(1)
            cur = {"kind": kind, "name": m.group(2), "members": [], "methods": []}
            (types if section != "errors" else types).append(cur)
            in_block = True
            continue
        m = re.match(r"pub(?:\(open\))?\s+trait\s+(\w+)\s*\{", s)
        if m:
            cur = {"kind": "trait", "name": m.group(1), "members": [], "methods": []}
            traits.append(cur)
            in_block = True
            continue
        m = re.match(r"^type (\w+)$", s)
        if m:
            types.append({"kind": "type", "name": m.group(1), "members": [], "methods": []})
            continue
        m = re.match(r"pub (?:async )?fn (\w+)::(\w+)\(", s)
        if m:
            owner = next(
                (t for t in types + traits if t["name"] == m.group(1)), None
            )
            if owner is not None:
                owner["methods"].append({"name": m.group(2), "sig": s})
            continue
        m = re.match(r"pub (?:async )?fn (\w+)\(", s)
        if m:
            values.append({"kind": "fn", "name": m.group(1), "sig": s})
            continue
        m = re.match(r"pub let (\w+)\s*:", s)
        if m:
            values.append({"kind": "let", "name": m.group(1), "sig": s})
            continue
        m = re.match(r"pub using (\w+) \{type (\w+)\}", s)
        if m:
            values.append(
                {"kind": "using", "name": m.group(2), "sig": f"pub using @{m.group(1)} {{type {m.group(2)}}}"}
            )
            continue
        m = re.match(r"pub impl (.+) for (\w+)", s)
        if m:
            impls.append(s)
            continue
    for t in types + traits:
        t["methods"] = sorted(
            [m for m in t["methods"] if m["name"] not in DERIVED],
            key=lambda m: m["name"],
        )
    return values, types, traits, impls


def render_desc(text):
    if not text:
        return ""
    text = html.escape(text)
    chunks = re.split(r"\n\s*\n", text.strip())
    out = []
    for c in chunks:
        c = re.sub(r"\s*\n\s*", " ", c)
        c = re.sub(r"`([^`]+)`", r"<code>\1</code>", c)
        out.append(f'<p class="api-desc">{c}</p>')
    return "\n".join(out)


def sig_html(sig, name=None):
    s = html.escape(sig)
    s = s.replace("-&gt;", '<span class="kw">-&gt;</span>')
    if name:
        target = html.escape(name)
        s = s.replace(target, f'<span class="fn">{target}</span>', 1)
    s = re.sub(
        r"^(pub fn|pub let|pub async fn|pub\(all\) struct|pub struct|pub\(all\) enum|"
        r"pub\(all\) suberror|pub\(open\) trait|type|pub using)",
        r'<span class="kw">\1</span>',
        s,
    )
    return s


def item(anchor, sig, doc, name=None, extra=""):
    return (
        f'<div class="api-item" id="{anchor}">'
        f'<div class="api-sig">{sig_html(sig, name)}</div>'
        f"{render_desc(doc)}"
        f"{extra}"
        "</div>"
    )


def package_block(slug, title, blurb, docs, values, types, traits, impls):
    prefix = slug.replace("/", "-") or "root"
    body = []
    toc = []
    body.append(f'<h2 class="api-pkg" id="pkg-{prefix}">{html.escape(title)}</h2>')
    body.append(f'<p class="api-blurb">{html.escape(blurb)}</p>')
    toc.append(f'<a href="#pkg-{prefix}" class="toc__pkg">{html.escape(title)}</a>')

    plain_values = [v for v in values if v["kind"] in ("fn", "let")]
    aliases = [v for v in values if v["kind"] == "using"]

    for v in plain_values:
        anchor = f"{prefix}-v-{v['name']}"
        toc.append(f'<a href="#{anchor}" class="toc-sub">{v["name"]}</a>')
        body.append(item(anchor, v["sig"], docs.get(v["name"], ""), v["name"]))

    for t in sorted(types, key=lambda t: t["name"]):
        anchor = f"{prefix}-t-{t['name']}"
        toc.append(f'<a href="#{anchor}" class="toc-sub">{t["name"]}</a>')
        kw = {
            "struct": "pub(all) struct",
            "enum": "pub(all) enum",
            "suberror": "pub(all) suberror",
            "type": "type",
        }[t["kind"]]
        sig = kw + " " + t["name"]
        head = (
            f'<div class="api-item" id="{anchor}">'
            f'<div class="api-sig">{sig_html(sig)}</div>'
            f"{render_desc(docs.get(t['name'], ''))}"
        )
        if t["members"]:
            rows = []
            for member in t["members"]:
                rows.append(f'<div class="api-sig api-sig--member">{sig_html(member)}</div>')
                vname = re.match(r"([A-Za-z0-9_]+)", member)
                if vname:
                    vdoc = docs.get(f"{t['name']}::{vname.group(1)}")
                    if vdoc:
                        rows.append(f'<div class="api-vdoc">{render_desc(vdoc)}</div>')
            head += '<div class="api-sub">' + "".join(rows) + "</div>"
        body.append(head + "</div>")
        for m in t["methods"]:
            manchor = f"{prefix}-m-{t['name']}-{m['name']}"
            toc.append(
                f'<a href="#{manchor}" class="toc-sub toc-sub--deep">{t["name"]}.{m["name"]}</a>'
            )
            body.append(
                item(
                    manchor,
                    m["sig"],
                    docs.get(f"{t['name']}::{m['name']}", ""),
                    m["name"],
                )
            )

    for t in traits:
        anchor = f"{prefix}-t-{t['name']}"
        toc.append(f'<a href="#{anchor}" class="toc-sub">{t["name"]}</a>')
        head = (
            f'<div class="api-item" id="{anchor}">'
            f'<div class="api-sig">{sig_html("pub(open) trait " + t["name"])}</div>'
            f"{render_desc(docs.get(t['name'], ''))}"
        )
        if t["members"]:
            rows = []
            for member in t["members"]:
                rows.append(f'<div class="api-sig api-sig--member">{sig_html(member)}</div>')
                mname = re.match(r"(?:async\s+)?fn\s+(\w+)", member)
                if mname:
                    vdoc = docs.get(f"{t['name']}::{mname.group(1)}")
                    if vdoc:
                        rows.append(f'<div class="api-vdoc">{render_desc(vdoc)}</div>')
            head += '<div class="api-sub">' + "".join(rows) + "</div>"
        body.append(head + "</div>")

    for a in aliases:
        anchor = f"{prefix}-a-{a['name']}"
        toc.append(f'<a href="#{anchor}" class="toc-sub">{a["name"]}</a>')
        body.append(item(anchor, a["sig"], docs.get(a["name"], ""), a["name"]))

    for impl in impls:
        body.append(f'<div class="api-sig api-sig--impl">{sig_html(impl)}</div>')

    return "\n".join(body), toc


def build():
    body = []
    toc = []
    index = []
    for slug, title, blurb in PACKAGES:
        directory = ROOT / "src" / slug if slug else ROOT / "src"
        mbti = directory / MBTI
        if not mbti.exists():
            raise SystemExit(f"no interface file for {title}: {mbti}")
        docs = parse_comments(sources_of(directory))
        values, types, traits, impls = parse_mbti(mbti)
        block, lines = package_block(slug, title, blurb, docs, values, types, traits, impls)
        body.append(block)
        toc.extend(lines)
        prefix = slug.replace("/", "-") or "root"
        index.append(f'<a href="#pkg-{prefix}">{html.escape(title)}</a>')

    page = TEMPLATE.format(
        toc="\n".join(toc),
        index="\n".join(index),
        body="\n".join(body),
    )
    OUT.write_text(page, encoding="utf-8", newline="\n")
    print(f"wrote {OUT.relative_to(ROOT)}")


TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>API reference · moonnet</title>
<meta name="description" content="Every public value, type, method and error in moonnet, generated from the package interfaces and their documentation comments.">
<link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'><rect width='32' height='32' rx='6' fill='%230C1116'/><path d='M6 11h20M6 21h20' stroke='%2340C8B4' stroke-width='2'/><circle cx='11' cy='11' r='2.4' fill='%23F0B357'/><circle cx='21' cy='21' r='2.4' fill='%23F0B357'/></svg>">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;500;600;700&family=Inter+Tight:wght@400;500;600&family=JetBrains+Mono:wght@400;500;700&display=swap" rel="stylesheet">
<link rel="stylesheet" href="assets/css/style.css">
</head>
<body class="page-api">
<a class="skip" href="#main">Skip to content</a>

<header class="nav">
  <a class="nav__brand" href="index.html" aria-label="moonnet home">
    <svg viewBox="0 0 32 24" aria-hidden="true"><path d="M2 6h28M2 18h28" stroke="currentColor" stroke-width="1.6"/><circle cx="9" cy="6" r="3" fill="none" stroke="currentColor" stroke-width="1.6"/><circle cx="23" cy="18" r="3" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>
    <span>moonnet</span>
  </a>
  <button class="nav__icon nav__menu" type="button" aria-label="Menu" aria-expanded="false">
    <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 7h16M4 12h16M4 17h16"/></svg>
  </button>
  <nav class="nav__links">
    <a class="nav__link" href="index.html">Home</a>
    <a class="nav__link" href="guide.html">Guide</a>
    <a class="nav__link is-active" href="api.html" aria-current="page">API</a>
    <a class="nav__link" href="showcase.html">Showcase</a>
    <a class="nav__link nav__link--ext" href="https://mooncakes.io/docs/moonbitstack/moonnet" title="mooncakes.io">mooncakes<svg class="nav__ext" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M7 17 17 7M9 7h8v8"/></svg></a>
    <a class="nav__icon" href="https://github.com/moonbitstack/moonnet" aria-label="GitHub repository" title="GitHub">
      <svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5C5.73.5.5 5.73.5 12a11.5 11.5 0 0 0 7.86 10.92c.58.1.79-.25.79-.56v-2c-3.2.7-3.88-1.37-3.88-1.37-.53-1.34-1.3-1.7-1.3-1.7-1.06-.72.08-.71.08-.71 1.17.08 1.79 1.2 1.79 1.2 1.04 1.79 2.73 1.27 3.4.97.1-.76.41-1.27.74-1.56-2.55-.29-5.23-1.28-5.23-5.7 0-1.26.45-2.29 1.19-3.1-.12-.29-.52-1.46.11-3.05 0 0 .97-.31 3.18 1.18a11 11 0 0 1 5.8 0c2.2-1.49 3.17-1.18 3.17-1.18.63 1.59.23 2.76.11 3.05.74.81 1.19 1.84 1.19 3.1 0 4.43-2.69 5.41-5.25 5.69.42.36.79 1.08.79 2.18v3.23c0 .31.21.67.8.56A11.5 11.5 0 0 0 23.5 12C23.5 5.73 18.27.5 12 .5Z"/></svg>
    </a>
    <button class="nav__icon nav__toggle" type="button" aria-label="Toggle theme" aria-pressed="false" title="Toggle theme">
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8Z"/></svg>
    </button>
  </nav>
</header>

<main id="main" class="wrap docs">
  <aside class="toc" aria-label="Contents">
{toc}
  </aside>
  <div class="content">
    <p class="eyebrow">API reference</p>
    <h1 class="page-title">The whole surface, by package.</h1>
    <p class="lead">Every public value, type, method and error, generated from the package interfaces and the comments beside the code.</p>
    <nav class="pkg-index" aria-label="Packages">
{index}
    </nav>
{body}
  </div>
</main>

<footer class="footer">
  <div class="wrap footer__row">
    <span>moonnet · Apache-2.0</span>
    <span>
      <a href="guide.html">Guide</a> ·
      <a href="showcase.html">Showcase</a> ·
      <a href="https://github.com/moonbitstack/moonnet">GitHub</a>
    </span>
  </div>
</footer>

<script src="assets/js/site.js" defer></script>
</body>
</html>
"""


if __name__ == "__main__":
    build()
