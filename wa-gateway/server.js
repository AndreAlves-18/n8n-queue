import express from "express";
import crypto from "crypto";
import fetch from "node-fetch";

const app = express();

// Captura raw body para validação da assinatura
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "";
const APP_SECRET = process.env.APP_SECRET || "";
const N8N_WEBHOOK_URL = process.env.N8N_WEBHOOK_URL || "";

// Verificação inicial do webhook (GET)
app.get("/webhook", (req, res) => {
  const mode = req.query["hub.mode"];
  const token = req.query["hub.verify_token"];
  const challenge = req.query["hub.challenge"];

  if (mode === "subscribe" && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// Recebimento de eventos (POST)
app.post("/webhook", async (req, res) => {
  try {
    if (APP_SECRET) {
      const sig = req.get("x-hub-signature-256") || "";
      const expected =
        "sha256=" +
        crypto
          .createHmac("sha256", APP_SECRET)
          .update(req.rawBody)
          .digest("hex");

      const sigBuf = Buffer.from(sig);
      const expBuf = Buffer.from(expected);

      if (
        sigBuf.length !== expBuf.length ||
        !crypto.timingSafeEqual(sigBuf, expBuf)
      ) {
        return res.sendStatus(401);
      }
    }

    const value = req.body?.entry?.[0]?.changes?.[0]?.value;
    const messages = value?.messages;
    const statuses = value?.statuses;

    // Ignora status (sent/delivered/read)
    if (!messages && statuses) {
      return res.sendStatus(200);
    }

    if (!messages) {
      return res.sendStatus(200);
    }

    // Encaminha apenas mensagens reais para o n8n
    const r = await fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req.body),
    });

    return res.sendStatus(r.ok ? 200 : 502);
  } catch (err) {
    console.error(err);
    return res.sendStatus(500);
  }
});

app.listen(3000, () => {
  console.log("WA Gateway listening on :3000");
});
