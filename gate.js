// Password gate for the GRN viewer site. Every data file on the site is encrypted (AES-256-GCM; key from the password
// with PBKDF2-SHA256, settings in auth.json next to this file). grnDecrypt(buffer) asks for the password once per
// browser tab, keeps the derived key in sessionStorage, and returns the decrypted bytes.
(() => {
  const BASE = new URL(".", document.currentScript.src).href, SKEY = "grnsite.key." + BASE;
  const enc = new TextEncoder(), dec = new TextDecoder();
  const b64d = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const b64e = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
  const ss = { get: (k) => { try { return sessionStorage.getItem(k); } catch (e) { return null; } },
    set: (k, v) => { try { sessionStorage.setItem(k, v); } catch (e) { /* private window: asked again next time */ } },
    del: (k) => { try { sessionStorage.removeItem(k); } catch (e) { /* nothing stored */ } } };
  const open = (key, buf) => { const u = new Uint8Array(buf); return crypto.subtle.decrypt({ name: "AES-GCM", iv: u.slice(0, 12) }, key, u.slice(12)); };
  const works = async (key, A) => { try { return dec.decode(await open(key, b64d(A.check))) === "grn-ok"; } catch (e) { return false; } };
  async function derive(pw, A) {
    const base = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: b64d(A.salt), iterations: A.iter, hash: "SHA-256" }, base,
      { name: "AES-GCM", length: 256 }, true, ["decrypt"]);
  }

  // the password form, drawn over the page
  let box = null;
  function ask(msg) {
    return new Promise((done) => {
      if (!box) {
        box = document.createElement("div");
        box.innerHTML = `<style>
          .grn-gate { --g-bg: #f6f7f9; --g-card: #fff; --g-ink: #1d2330; --g-muted: #5b6475; --g-line: #d5dae3; --g-accent: #1f5fbf; --g-bad: #b3261e;
            position: fixed; inset: 0; z-index: 99999; display: grid; place-items: center; background: var(--g-bg); color: var(--g-ink);
            font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; padding: 16px; }
          @media (prefers-color-scheme: dark) { .grn-gate { --g-bg: #14171d; --g-card: #1b1f27; --g-ink: #e6e9ef; --g-muted: #a3abba; --g-line: #2f3542; --g-accent: #7aa7ff; --g-bad: #ff8a80; } }
          .grn-gate form { background: var(--g-card); border: 1px solid var(--g-line); border-radius: 10px; padding: 24px; width: min(360px, 100%); display: grid; gap: 12px; }
          .grn-gate h1 { font-size: 18px; margin: 0; } .grn-gate p { margin: 0; color: var(--g-muted); font-size: 14px; }
          .grn-gate input { font: inherit; padding: 8px 10px; border: 1px solid var(--g-line); border-radius: 6px; background: var(--g-bg); color: var(--g-ink); }
          .grn-gate button { font: inherit; font-weight: 600; padding: 8px 10px; border: 0; border-radius: 6px; background: var(--g-accent); color: #fff; cursor: pointer; }
          .grn-gate button:disabled { opacity: .6; cursor: wait; } .grn-gate .bad { color: var(--g-bad); }
          .grn-gate input:focus-visible, .grn-gate button:focus-visible { outline: 2px solid var(--g-accent); outline-offset: 2px; }
        </style>
        <div class="grn-gate"><form id="grn-gate-form" autocomplete="off">
          <h1>GRN viewer</h1><p>This site is password protected.</p>
          <label for="grn-gate-pw" style="font-size:14px">Password</label>
          <input id="grn-gate-pw" type="password" required autofocus>
          <p id="grn-gate-msg" class="bad" role="alert"></p>
          <button id="grn-gate-go" type="submit">Open</button>
        </form></div>`;
        document.body.appendChild(box);
      }
      box.hidden = false;
      const f = box.querySelector("#grn-gate-form"), pw = box.querySelector("#grn-gate-pw"), go = box.querySelector("#grn-gate-go");
      box.querySelector("#grn-gate-msg").textContent = msg || ""; go.disabled = false; go.textContent = "Open"; pw.value = ""; pw.focus();
      f.onsubmit = (e) => { e.preventDefault(); go.disabled = true; go.textContent = "Checking…"; done(pw.value); };
    });
  }

  let keyP = null;
  function getKey() {
    return keyP ||= (async () => {
      const r = await fetch(BASE + "auth.json", { cache: "no-store" });
      if (!r.ok) throw new Error(`auth.json ${r.status}`);
      const A = await r.json(), saved = ss.get(SKEY);
      if (saved) {
        try { const k = await crypto.subtle.importKey("raw", b64d(saved), "AES-GCM", true, ["decrypt"]); if (await works(k, A)) return k; } catch (e) { /* fall through */ }
        ss.del(SKEY);
      }
      const prompt = window.grnAsk || ask;           // grnAsk: test hook
      for (let msg = ""; ; msg = "Wrong password. Try again.") {
        const k = await derive(await prompt(msg), A);
        if (await works(k, A)) { ss.set(SKEY, b64e(await crypto.subtle.exportKey("raw", k))); if (box) box.hidden = true; return k; }
      }
    })();
  }

  window.grnDecrypt = async (buf) => {
    const k = await getKey();
    try { return await open(k, buf); } catch (e) {
      ss.del(SKEY); keyP = null;
      throw new Error("A data file could not be decrypted, probably because the site was rebuilt. Reload the page and enter the password again.");
    }
  };
})();
