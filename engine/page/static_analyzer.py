"""DOM/static analysis: forms, scripts, metas, honeypot candidates, PII stripping."""

from __future__ import annotations

import re

from engine.artifacts import DomSummary, FormInfo, MetaInfo

MAX_RAW_HTML_BYTES = 2_000_000
MAX_INLINE_SAMPLE = 2000

EXTRACT_DOM_JS = r"""
() => {
  const abs = (v) => { try { return v ? new URL(v, document.baseURI).href : ''; } catch(e) { return v || ''; } };
  const honeypotish = (el) => {
    try {
      const cs = getComputedStyle(el);
      if (el.offsetParent === null && cs.position !== 'fixed') return true;
      if (cs.display === 'none' || cs.visibility === 'hidden') return true;
      if (parseInt(cs.width) <= 1 || parseInt(cs.height) <= 1) return true;
      const r = el.getBoundingClientRect();
      if (r.left < -50 || r.top < -50) return true;
      if ((el.tabIndex ?? 0) < 0 && el.getAttribute('aria-hidden') === 'true') return true;
    } catch(e) {}
    return false;
  };
  const forms = Array.from(document.forms).map(f => ({
    action: abs(f.action),
    method: (f.method || 'get').toUpperCase(),
    fields: Array.from(f.querySelectorAll('input,textarea')).map(i => ({
      name: i.name || i.id || '',
      type: i.type || 'text',
      autocomplete: i.getAttribute('autocomplete'),
      maxlength: i.maxLength >= 0 ? i.maxLength : null,
      honeypot_candidate: i.type === 'hidden' ? false : honeypotish(i),
      hidden: i.type === 'hidden',
      value_sample: i.type === 'hidden' ? String(i.value || '').slice(0, 120) : '',
    })),
  }));
  return {
    title: document.title || '',
    rawHtml: document.documentElement.outerHTML.slice(0, 2000000),
    forms,
    scripts: Array.from(document.scripts)
      .map(s => s.src ? abs(s.src) : '')
      .filter(Boolean),
    inlineScripts: Array.from(document.scripts)
      .filter(s => !s.src && s.textContent && s.textContent.trim().length > 0)
      .map(s => s.textContent.slice(0, 2000)),
    iframes: Array.from(document.querySelectorAll('iframe'))
      .map(f => abs(f.src))
      .filter(Boolean),
    metas: Array.from(document.querySelectorAll('meta')).slice(0, 60).map(m => ({
      name: m.name || m.getAttribute('property') || '',
      attribute: m.name ? 'name' : (m.getAttribute('property') ? 'property' : 'name'),
      content: String(m.content || '').slice(0, 500),
    })),
    bodyTextSample: (document.body ? document.body.innerText : '').slice(0, 4000),
  };
}
"""

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
_PHONE_RE = re.compile(r"(?<!\w)(?:\+?\d[\d\s().-]{7,}\d)(?!\w)")
_TOKEN_RE = re.compile(r"\b(?:eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,})\b")


def strip_pii(html: str) -> str:
    html = _EMAIL_RE.sub("[REDACTED_EMAIL]", html)
    html = _TOKEN_RE.sub("[REDACTED_TOKEN]", html)
    html = _PHONE_RE.sub("[REDACTED_PHONE]", html)
    return html


def build_dom_summary(data: dict) -> DomSummary:
    """Convert raw extractor output into a DomSummary with PII stripped."""
    from engine.artifacts import FormField

    forms: list[FormInfo] = []
    for f in data.get("forms", []):
        fields = [
            FormField(
                name=fd.get("name", ""),
                type=fd.get("type", "text"),
                autocomplete=fd.get("autocomplete"),
                maxlength=fd.get("maxlength"),
                honeypot_candidate=bool(fd.get("honeypot_candidate")),
            )
            for fd in f.get("fields", [])
        ]
        forms.append(FormInfo(action=f.get("action", ""), method=f.get("method", "GET"), fields=fields))

    raw_html = strip_pii(str(data.get("rawHtml", ""))[:MAX_RAW_HTML_BYTES])
    body_text = strip_pii(str(data.get("bodyTextSample", "")))

    return DomSummary(
        title=str(data.get("title", "")),
        raw_html=raw_html,
        forms=forms,
        scripts=[str(s) for s in data.get("scripts", [])],
        inline_scripts=[str(s)[:MAX_INLINE_SAMPLE] for s in data.get("inlineScripts", [])],
        iframes=[str(i) for i in data.get("iframes", [])],
        metas=[
            MetaInfo(name=m.get("name", ""), attribute=m.get("attribute", "name"), content=m.get("content", ""))
            for m in data.get("metas", [])
        ],
        body_text_sample=body_text,
    )
