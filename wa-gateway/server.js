import express from "express";
import crypto from "crypto";

const app = express();

// Captura raw body
app.use(express.json({
  verify: (req, res, buf) => {
    req.rawBody = buf;
  }
}));

const VERIFY_TOKEN = process.env.VERIFY_TOKEN || "";
// FIX 1: .trim() para evitar erro de nova linha em Docker
const APP_SECRET = (process.env.APP_SECRET || "").trim(); 
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
    if (APP_SECRET) {
      const sig = req.get("x-hub-signature-256") || "";
      
      // FIX 2: Garantir que rawBody existe
      if (!req.rawBody) {
        console.error("ERRO: req.rawBody está undefined. O middleware express.json falhou ou content-type incorreto.");
        return res.sendStatus(400);
      }

      const expected =
        "sha256=" +
        crypto
          .createHmac("sha256", APP_SECRET)
          .update(req.rawBody)
          .digest("hex");

      const sigBuf = Buffer.from(sig);
      const expBuf = Buffer.from(expected);

      // DEBUG: Remova em produção
      if (sig !== expected) {
          console.log(`Mismatch! \nSecret Len: ${APP_SECRET.length} \nRecebido: ${sig} \nGerado:   ${expected}`);
      }

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

    const hasMessages = Array.isArray(value?.messages) && value.messages.length > 0;
    const hasStatuses = Array.isArray(value?.statuses) && value.statuses.length > 0;

    if(!hasMessages && hasStatuses) return res.sendStatus(200);
    if(!hasMessages) return res.sendStatus(200);


    // Ignora status para não inundar o n8n
    if (!messages && statuses) {
      return res.sendStatus(200);
    }

    if (!messages) {
      return res.sendStatus(200);
    }

    // Encaminha para o n8n
    // RESPONDE IMEDIATO para evitar retry da Meta
    res.sendStatus(200);
    
    // Encaminha para o n8n em background (sem travar o ACK)
    fetch(N8N_WEBHOOK_URL, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(req.body),
    })
      .then((r) => {
        if (!r.ok) console.error("Falha ao enviar ao n8n:", r.status);
      })
      .catch((err) => {
        console.error("Erro ao enviar ao n8n:", err);
      });
    return;
    
  } catch (err) {
    console.error(err);
    return res.sendStatus(500);
  }
});

app.listen(3000, () => {
  console.log("WA Gateway listening on :3000");
});
