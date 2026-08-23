"""Early runtime hooks injected via evaluateOnNewDocument before any page script.

Captures fetch/XHR calls and canvas/WebGL fingerprint-read counters into
``window.__authscope``; drained by the page controller at scan end.
Hooks are defensive (try/catch) and never alter page behavior.
"""

from __future__ import annotations

HOOKS_JS = r"""
(() => {
  if (window.__authscope) { return; }
  const state = {
    hookLog: [],
    fingerprintReads: {
      canvas_dataurl: 0,
      canvas_imagedata: 0,
      webgl_readpixels: 0,
    },
  };
  window.__authscope = state;

  const safe = (fn) => { try { return fn(); } catch (e) { return undefined; } };

  // --- fetch wrapper ---
  safe(() => {
    const origFetch = window.fetch;
    if (!origFetch) { return; }
    window.fetch = function(input, init) {
      try {
        const url = typeof input === 'string' ? input :
          (input && input.url) ? input.url : String(input);
        const method = (init && init.method) ||
          (input && input.method) || 'GET';
        state.hookLog.push({kind: 'fetch', method: String(method), url: String(url)});
      } catch (e) {}
      return origFetch.apply(this, arguments);
    };
  });

  // --- XHR wrapper ---
  safe(() => {
    const origOpen = XMLHttpRequest.prototype.open;
    XMLHttpRequest.prototype.open = function(method, url) {
      try {
        this.__asMethod = String(method);
        this.__asUrl = String(url);
        this.addEventListener('load', () => {
          try {
            state.hookLog.push({
              kind: 'xhr', method: this.__asMethod || 'GET',
              url: this.__asUrl || '', status: this.status,
            });
          } catch (e) {}
        });
      } catch (e) {}
      return origOpen.apply(this, arguments);
    };
  });

  // --- fingerprint read counters ---
  safe(() => {
    const proto = HTMLCanvasElement.prototype;
    const origToDataURL = proto.toDataURL;
    proto.toDataURL = function() {
      try { state.fingerprintReads.canvas_dataurl += 1; } catch (e) {}
      return origToDataURL.apply(this, arguments);
    };
    const ctxProto = CanvasRenderingContext2D.prototype;
    const origGetImageData = ctxProto.getImageData;
    ctxProto.getImageData = function() {
      try { state.fingerprintReads.canvas_imagedata += 1; } catch (e) {}
      return origGetImageData.apply(this, arguments);
    };
  });
  safe(() => {
    if (typeof WebGLRenderingContext === 'undefined') { return; }
    const proto = WebGLRenderingContext.prototype;
    const orig = proto.readPixels;
    proto.readPixels = function() {
      try { state.fingerprintReads.webgl_readpixels += 1; } catch (e) {}
      return orig.apply(this, arguments);
    };
  });
})();
"""


def drain_hooks_js() -> str:
    """Expression evaluated at scan end: returns and clears collected data."""
    return """
    (() => {
      if (!window.__authscope) {
        return {hookLog: [], fingerprintReads: {}};
      }
      const out = {
        hookLog: window.__authscope.hookLog.slice(0, 2000),
        fingerprintReads: Object.assign({}, window.__authscope.fingerprintReads),
      };
      window.__authscope.hookLog.length = 0;
      return out;
    })()
    """


GLOBALS_PROBE_JS = "Object.getOwnPropertyNames(window)"
