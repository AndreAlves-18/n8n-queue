import express from "express";
import crypto from "crypto";

const app = express();

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "";
const APP_SECRET = process.env.APP_SECRET || "";
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL || "";

// GET para verificação do webhook
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// helper: comparação segura
function safeEqual(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

// POST: usa raw body para assinatura
app.post("/webhook", express.raw({ type: "application/json" }), async (req, res) => {
  try {
    // 1) valida assinatura (se APP_SECRET estiver setado)
    if (APP_SECRET) {
      const sig = req.get("x-hub-signature-256") || "";
      const expected =
        "sha256=" + crypto.createHmac("sha256", APP_SECRET).update(req.body).digest("hex");

      if (!sig || !safeEqual(sig, expected)) {
        return res.sendStatus(401);
      }
    }

    // 2) parse do JSON
    const body = JSON.parse(req.body.toString("utf8"));

    const value = body?.entry?.[0]?.changes?.[0]?.value;
    const hasMessages = Array.isArray(value?.messages) && value.messages.length > 0;
    const hasStatuses = Array.isArray(value?.statuses) && value.statuses.length > 0;

    // 3) ignora status
    if (!hasMessages && hasStatuses) return res.sendStatus(200);
    if (!hasMessages) return res.sendStatus(200);

    // 4) encaminha mensagens pro n8n
    const r = await fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    return res.sendStatus(r.ok ? 200 : 502);
  } catch (e) {
    console.error("[ERR]", e);
    return res.sendStatus(500);
  }
});

app.listen(3000, () => {
  console.log("WA Gateway listening on :3000");
});
