import express from "express";
import crypto from "crypto";

const app = express();

// Precisamos do raw body para validar assinatura (X-Hub-Signature-256)
app.use(express.json({
  verify: (req, res, buf) => { req.rawBody = buf; }
}));

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "";
const APP_SECRET = process.env.APP_SECRET || "";
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL || "";

app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

app.post("/webhook", async (req, res) => {
  try {
    // Validação de assinatura 
    if (APP_SECRET) {
      const sig = req.header("x-hub-signature-256") || "";
      const expected = "sha256=" + crypto
        .createHmac("sha256", APP_SECRET)
        .update(req.rawBody)
        .digest("hex");

      if (!timingSafeEqual(sig, expected)) {
        return res.sendStatus(401);
      }
    }

    const body = req.body;
    const value = body?.entry?.[0]?.changes?.[0]?.value;

    const hasMessages = Array.isArray(value?.messages) && value.messages.length > 0;
    const hasStatuses = Array.isArray(value?.statuses) && value.statuses.length > 0;

    // Ignora ACKs/status (sent/delivered/read) — não executa n8n
    if (!hasMessages && hasStatuses) {
      return res.sendStatus(200);
    }

    // Se não tem nada útil, ignora também
    if (!hasMessages) {
      return res.sendStatus(200);
    }

    // Encaminha só mensagens reais para o n8n-webhooks
    const r = await fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    });

    return res.sendStatus(r.ok ? 200 : 502);
  } catch (err) {
    return res.sendStatus(500);
  }
});

function timingSafeEqual(a, b) {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return crypto.timingSafeEqual(ab, bb);
}

app.listen(3000, () => console.log("WA Gateway listening on :3000"));
