/**
 * Zero-Knowledge Secret Santa
 * Pure client-side AES-GCM encryption & derangement cycle engine.
 */

// --- Base64URL Helpers ---
function base64UrlToBytes(b64url) {
  let b64 = b64url.replace(/-/g, "+").replace(/_/g, "/");
  while (b64.length % 4) b64 += "=";
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function bytesToBase64Url(bytes) {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// --- Confetti Particle System ---
class ConfettiCannon {
  constructor(canvas) {
    this.canvas = canvas;
    this.ctx = canvas.getContext("2d");
    this.particles = [];
    this.animationId = null;
    this.colors = ["#b91c1c", "#15803d", "#fbbf24", "#f3f4f6", "#d97706", "#22c55e"];
    this.resize();
    window.addEventListener("resize", () => this.resize());
  }

  resize() {
    this.canvas.width = window.innerWidth;
    this.canvas.height = window.innerHeight;
  }

  burst(x, y, count = 70) {
    // Check prefers-reduced-motion
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      return;
    }

    for (let i = 0; i < count; i++) {
      const angle = (Math.random() * Math.PI * 1.5) - (Math.PI * 0.75); // upward fan
      const velocity = 8 + Math.random() * 12;
      this.particles.push({
        x: x || this.canvas.width / 2,
        y: y || this.canvas.height / 2,
        vx: Math.cos(angle) * velocity + (Math.random() - 0.5) * 4,
        vy: Math.sin(angle) * velocity - 3,
        size: 5 + Math.random() * 6,
        color: this.colors[Math.floor(Math.random() * this.colors.length)],
        rotation: Math.random() * 360,
        rotationSpeed: (Math.random() - 0.5) * 10,
        gravity: 0.35,
        opacity: 1,
        life: 120 + Math.random() * 60,
      });
    }

    if (!this.animationId) {
      this.animate();
    }
  }

  animate() {
    this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);

    for (let i = this.particles.length - 1; i >= 0; i--) {
      const p = this.particles[i];
      p.x += p.vx;
      p.y += p.vy;
      p.vy += p.gravity;
      p.rotation += p.rotationSpeed;
      p.life--;
      p.opacity = Math.max(0, p.life / 60);

      this.ctx.save();
      this.ctx.translate(p.x, p.y);
      this.ctx.rotate((p.rotation * Math.PI) / 180);
      this.ctx.fillStyle = p.color;
      this.ctx.globalAlpha = Math.min(1, p.opacity);
      this.ctx.fillRect(-p.size / 2, -p.size / 2, p.size, p.size * 1.4);
      this.ctx.restore();

      if (p.life <= 0 || p.y > this.canvas.height + 50) {
        this.particles.splice(i, 1);
      }
    }

    if (this.particles.length > 0) {
      this.animationId = requestAnimationFrame(() => this.animate());
    } else {
      this.ctx.clearRect(0, 0, this.canvas.width, this.canvas.height);
      this.animationId = null;
    }
  }
}

// --- Web Crypto AES-GCM Engine ---
async function decryptPayload(payloadB64, keyB64) {
  const keyBytes = base64UrlToBytes(keyB64);
  const payloadBytes = base64UrlToBytes(payloadB64);

  if (payloadBytes.length < 12 + 16) {
    throw new Error("Payload too short to contain IV and ciphertext.");
  }

  const nonce = payloadBytes.slice(0, 12);
  const ciphertext = payloadBytes.slice(12);

  const cryptoKey = await window.crypto.subtle.importKey(
    "raw",
    keyBytes,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  const decryptedBuffer = await window.crypto.subtle.decrypt(
    { name: "AES-GCM", iv: nonce },
    cryptoKey,
    ciphertext
  );

  const text = new TextDecoder().decode(decryptedBuffer);
  return JSON.parse(text);
}

async function encryptData(dataObj) {
  const text = JSON.stringify(dataObj);
  const plaintextBytes = new TextEncoder().encode(text);

  const key = await window.crypto.subtle.generateKey(
    { name: "AES-GCM", length: 128 },
    true,
    ["encrypt", "decrypt"]
  );

  const nonce = window.crypto.getRandomValues(new Uint8Array(12));

  const ciphertextBuffer = await window.crypto.subtle.decrypt
    ? await window.crypto.subtle.encrypt(
        { name: "AES-GCM", iv: nonce },
        key,
        plaintextBytes
      )
    : null;

  const rawKey = await window.crypto.subtle.exportKey("raw", key);

  // Combine nonce + ciphertext
  const combined = new Uint8Array(nonce.length + ciphertextBuffer.byteLength);
  combined.set(nonce, 0);
  combined.set(new Uint8Array(ciphertextBuffer), nonce.length);

  return {
    payloadB64: bytesToBase64Url(combined),
    keyB64: bytesToBase64Url(new Uint8Array(rawKey)),
  };
}

// --- Derangement Cycle Algorithm (Sattolo's Algorithm) ---
function secureRandomInt(max) {
  // Returns cryptographically random integer in [0, max - 1]
  const array = new Uint32Array(1);
  const maxUint = 0xffffffff;
  const limit = maxUint - (maxUint % max);
  let val;
  do {
    window.crypto.getRandomValues(array);
    val = array[0];
  } while (val >= limit);
  return val % max;
}

function generateDerangementCycle(names, exclusions = {}, maxAttempts = 5000) {
  const n = names.length;
  if (n < 2) throw new Error("At least 2 names are required.");

  for (let attempt = 0; attempt < maxAttempts; attempt++) {
    const pool = [...names];
    for (let i = n - 1; i > 0; i--) {
      const j = secureRandomInt(i); // 0 <= j < i
      const tmp = pool[i];
      pool[i] = pool[j];
      pool[j] = tmp;
    }

    let valid = true;
    const pairs = [];
    for (let k = 0; k < n; k++) {
      const giver = pool[k];
      const receiver = pool[(k + 1) % n];
      const blocked = exclusions[giver] || new Set();
      if (giver === receiver || blocked.has(receiver)) {
        valid = false;
        break;
      }
      pairs.append ? pairs.append([giver, receiver]) : pairs.push([giver, receiver]);
    }
    if (valid) return pairs;
  }

  // Fallback: randomized backtracking
  function backtrack(currentCycle, remaining) {
    if (remaining.size === 0) {
      const last = currentCycle[currentCycle.length - 1];
      const first = currentCycle[0];
      const blocked = exclusions[last] || new Set();
      if (blocked.has(first) || last === first) return null;
      return currentCycle;
    }
    const currentGiver = currentCycle[currentCycle.length - 1];
    const blocked = exclusions[currentGiver] || new Set();
    const candidates = Array.from(remaining).filter(
      (c) => c !== currentGiver && !blocked.has(c)
    );
    // Shuffle candidates
    for (let i = candidates.length - 1; i > 0; i--) {
      const j = secureRandomInt(i + 1);
      [candidates[i], candidates[j]] = [candidates[j], candidates[i]];
    }

    for (const next of candidates) {
      remaining.delete(next);
      currentCycle.push(next);
      const res = backtrack(currentCycle, remaining);
      if (res) return res;
      currentCycle.pop();
      remaining.add(next);
    }
    return null;
  }

  const shuffledNames = [...names];
  for (let i = shuffledNames.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [shuffledNames[i], shuffledNames[j]] = [shuffledNames[j], shuffledNames[i]];
  }

  const startPerson = shuffledNames[0];
  const remainingSet = new Set(shuffledNames.slice(1));
  const cycle = backtrack([startPerson], remainingSet);

  if (!cycle) {
    throw new Error("No valid Secret Santa pairings possible with these exclusion rules.");
  }

  const pairs = [];
  for (let k = 0; k < n; k++) {
    pairs.push([cycle[k], cycle[(k + 1) % n]]);
  }
  return pairs;
}

// --- UI Management ---
document.addEventListener("DOMContentLoaded", () => {
  const canvas = document.getElementById("confetti-canvas");
  const confetti = new ConfettiCannon(canvas);

  const viewReveal = document.getElementById("view-reveal");
  const viewError = document.getElementById("view-error");
  const viewGenerator = document.getElementById("view-generator");

  const revealGiverName = document.getElementById("reveal-giver-name");
  const revealRecipient = document.getElementById("reveal-recipient");
  const giftWrapper = document.getElementById("gift-wrapper");
  const unwrappedContent = document.getElementById("unwrapped-content");
  const metaDetails = document.getElementById("meta-details");
  const metaBudgetRow = document.getElementById("meta-budget-row");
  const metaBudget = document.getElementById("meta-budget");
  const metaNoteRow = document.getElementById("meta-note-row");
  const metaNote = document.getElementById("meta-note");

  const btnCopyRecipient = document.getElementById("btn-copy-recipient");
  const btnRehide = document.getElementById("btn-rehide");
  const btnGoHome = document.getElementById("btn-go-home");
  const errorMessage = document.getElementById("error-message");

  const drawForm = document.getElementById("draw-form");
  const inputNames = document.getElementById("input-names");
  const inputBudget = document.getElementById("input-budget");
  const inputNote = document.getElementById("input-note");
  const inputExclusions = document.getElementById("input-exclusions");
  const generatorResults = document.getElementById("generator-results");
  const linksList = document.getElementById("links-list");
  const btnCopyAll = document.getElementById("btn-copy-all");
  const btnDownloadTxt = document.getElementById("btn-download-txt");

  let currentDrawLinks = []; // Holds { giver, link }

  // 1. Router based on location.hash
  async function route() {
    const hash = window.location.hash.substring(1).trim();

    if (!hash) {
      showView(viewGenerator);
      return;
    }

    if (!hash.includes(".")) {
      showError("Invalid link format. Missing encryption key fragment.");
      return;
    }

    const dotIndex = hash.indexOf(".");
    const payloadB64 = hash.substring(0, dotIndex);
    const keyB64 = hash.substring(dotIndex + 1);

    try {
      const data = await decryptPayload(payloadB64, keyB64);
      displayReveal(data);
    } catch (err) {
      console.error("Decryption error:", err);
      showError("Could not decrypt this link. The key or payload may be damaged.");
    }
  }

  function showView(targetView) {
    [viewReveal, viewError, viewGenerator].forEach((v) => v.classList.add("hidden"));
    targetView.classList.remove("hidden");
  }

  function showError(msg) {
    errorMessage.textContent = msg;
    showView(viewError);
  }

  function displayReveal(data) {
    revealGiverName.textContent = data.giver || "Participant";
    revealRecipient.textContent = data.recipient || "Secret Friend";

    let hasMeta = false;
    if (data.budget && data.budget.trim()) {
      metaBudget.textContent = data.budget.trim();
      metaBudgetRow.classList.remove("hidden");
      hasMeta = true;
    } else {
      metaBudgetRow.classList.add("hidden");
    }

    if (data.note && data.note.trim()) {
      metaNote.textContent = data.note.trim();
      metaNoteRow.classList.remove("hidden");
      hasMeta = true;
    } else {
      metaNoteRow.classList.add("hidden");
    }

    if (hasMeta) {
      metaDetails.classList.remove("hidden");
    } else {
      metaDetails.classList.add("hidden");
    }

    // Reset box to sealed
    giftWrapper.classList.remove("hidden");
    unwrappedContent.classList.add("hidden");

    showView(viewReveal);
  }

  // 2. Gift Unwrap Interaction
  function unwrapGift() {
    const rect = giftWrapper.getBoundingClientRect();
    const centerX = rect.left + rect.width / 2;
    const centerY = rect.top + rect.height / 2;

    giftWrapper.classList.add("hidden");
    unwrappedContent.classList.remove("hidden");

    confetti.burst(centerX, centerY, 80);
  }

  giftWrapper.addEventListener("click", unwrapGift);
  giftWrapper.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") {
      e.preventDefault();
      unwrapGift();
    }
  });

  // Re-hide button
  btnRehide.addEventListener("click", () => {
    unwrappedContent.classList.add("hidden");
    giftWrapper.classList.remove("hidden");
  });

  // Copy Recipient Name
  btnCopyRecipient.addEventListener("click", async () => {
    const name = revealRecipient.textContent;
    try {
      await navigator.clipboard.writeText(name);
      const span = btnCopyRecipient.querySelector("span");
      const original = span.textContent;
      span.textContent = "Copied! ✓";
      setTimeout(() => {
        span.textContent = original;
      }, 2000);
    } catch (e) {
      alert(`Recipient: ${name}`);
    }
  });

  btnGoHome.addEventListener("click", (e) => {
    e.preventDefault();
    history.pushState("", document.title, window.location.pathname + window.location.search);
    route();
  });

  // 3. Organizer Generator Submission
  drawForm.addEventListener("submit", async (e) => {
    e.preventDefault();

    const rawNames = inputNames.value
      .split("\n")
      .map((n) => n.trim())
      .filter((n) => n.length > 0);

    if (rawNames.length < 2) {
      alert("Please provide at least 2 participant names.");
      return;
    }

    // Parse exclusions
    const exclusions = {};
    const rawExcl = inputExclusions.value.split("\n");
    for (let line of rawExcl) {
      line = line.trim();
      if (!line) continue;
      if (line.includes("->")) {
        const [a, b] = line.split("->").map((s) => s.trim());
        if (a && b) {
          if (!exclusions[a]) exclusions[a] = new Set();
          exclusions[a].add(b);
        }
      } else if (line.includes(":")) {
        const [a, b] = line.split(":").map((s) => s.trim());
        if (a && b) {
          if (!exclusions[a]) exclusions[a] = new Set();
          if (!exclusions[b]) exclusions[b] = new Set();
          exclusions[a].add(b);
          exclusions[b].add(a);
        }
      }
    }

    const budget = inputBudget.value.trim();
    const note = inputNote.value.trim();

    try {
      const pairs = generateDerangementCycle(rawNames, exclusions);

      // Base URL without hash
      const baseUrl = window.location.origin + window.location.pathname;

      currentDrawLinks = [];
      for (const [giver, receiver] of pairs) {
        const payloadObj = {
          giver,
          recipient: receiver,
        };
        if (budget) payloadObj.budget = budget;
        if (note) payloadObj.note = note;

        const { payloadB64, keyB64 } = await encryptData(payloadObj);
        const link = `${baseUrl}#${payloadB64}.${keyB64}`;
        currentDrawLinks.push({ giver, link });
      }

      // Sort alphabetically by giver name to break topological cycle order!
      currentDrawLinks.sort((a, b) => a.giver.localeCompare(b.giver));

      renderGeneratedLinks();
    } catch (err) {
      alert(`Error generating draw: ${err.message}`);
    }
  });

  function renderGeneratedLinks() {
    linksList.innerHTML = "";
    currentDrawLinks.forEach(({ giver, link }) => {
      const li = document.createElement("li");
      li.className = "link-item";

      const giverSpan = document.createElement("span");
      giverSpan.className = "link-giver";
      giverSpan.textContent = giver;

      const urlPreview = document.createElement("span");
      urlPreview.className = "link-url-preview";
      urlPreview.textContent = link;

      const copyBtn = document.createElement("button");
      copyBtn.className = "btn btn-outline btn-copy-small";
      copyBtn.textContent = "Copy Link";
      copyBtn.addEventListener("click", async () => {
        try {
          await navigator.clipboard.writeText(link);
          copyBtn.textContent = "Copied! ✓";
          setTimeout(() => {
            copyBtn.textContent = "Copy Link";
          }, 2000);
        } catch (e) {
          prompt("Copy this link:", link);
        }
      });

      li.appendChild(giverSpan);
      li.appendChild(urlPreview);
      li.appendChild(copyBtn);
      linksList.appendChild(li);
    });

    generatorResults.classList.remove("hidden");
    generatorResults.scrollIntoView({ behavior: "smooth" });
  }

  // Copy all links
  btnCopyAll.addEventListener("click", async () => {
    if (currentDrawLinks.length === 0) return;
    const text = currentDrawLinks
      .map(({ giver, link }) => `${giver.padEnd(16)}: ${link}`)
      .join("\n");
    try {
      await navigator.clipboard.writeText(text);
      const span = btnCopyAll.querySelector("span");
      const orig = span.textContent;
      span.textContent = "All Links Copied! ✓";
      setTimeout(() => {
        span.textContent = orig;
      }, 2000);
    } catch (e) {
      alert("Could not copy automatically. You can copy individual links below.");
    }
  });

  // Download .txt
  btnDownloadTxt.addEventListener("click", () => {
    if (currentDrawLinks.length === 0) return;
    const text = [
      "============================================================",
      "🎄 SECRET SANTA DISTRIBUTION LINKS (ZERO-KNOWLEDGE)",
      "============================================================",
      "Send each person their private link below.",
      "DO NOT OPEN OTHER PEOPLE'S LINKS!",
      "------------------------------------------------------------",
      ...currentDrawLinks.map(({ giver, link }) => `${giver.padEnd(16)}: ${link}`),
      "============================================================",
    ].join("\n");

    const blob = new Blob([text], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "secret-santa-links.txt";
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  });

  // Listen to hash changes
  window.addEventListener("hashchange", route);

  // Initial route
  route();
});
