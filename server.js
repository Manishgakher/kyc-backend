require("dotenv").config();
const express = require("express");
const cors = require("cors");
const app = express();

app.use(cors({ origin: process.env.FRONTEND_URL || "*", methods: ["GET","POST"], allowedHeaders: ["Content-Type","Authorization"] }));
app.use(express.json({ limit: "20mb" }));
app.get("/", (req, res) => res.json({ status: "ok", service: "KYC Verify API" }));

const otpStore = new Map();
const OTP_TTL_MS = 10 * 60 * 1000;
setInterval(() => { const now = Date.now(); for (const [k,v] of otpStore.entries()) { if (now > v.expiresAt) otpStore.delete(k); } }, 5 * 60 * 1000);
function genOTP() { return String(Math.floor(100000 + Math.random() * 900000)); }

app.post("/otp/send", async (req, res) => {
  const { type, destination } = req.body;
  if (!type || !destination) return res.status(400).json({ error: "type and destination required" });
  if (!["email","sms"].includes(type)) return res.status(400).json({ error: "type must be email or sms" });
  const code = genOTP();
  otpStore.set(type+":"+destination, { code, expiresAt: Date.now()+OTP_TTL_MS, attempts: 0 });
  try {
    if (type === "sms") await sendSMS(destination, code);
    else await sendEmail(destination, code);
    console.log("[OTP] Sent "+type+" to "+destination);
    res.json({ success: true });
  } catch(err) {
    console.error("[OTP] Error:", err.message);
    otpStore.delete(type+":"+destination);
    res.status(500).json({ error: err.message || "Failed to send OTP" });
  }
});

app.post("/otp/verify", (req, res) => {
  const { type, destination, code } = req.body;
  if (!type || !destination || !code) return res.status(400).json({ error: "type, destination and code required" });
  const stored = otpStore.get(type+":"+destination);
  if (!stored) return res.status(400).json({ error: "OTP not found or expired. Request a new one." });
  if (Date.now() > stored.expiresAt) { otpStore.delete(type+":"+destination); return res.status(400).json({ error: "OTP expired." }); }
  stored.attempts = (stored.attempts||0)+1;
  if (stored.attempts > 5) { otpStore.delete(type+":"+destination); return res.status(429).json({ error: "Too many attempts. Request a new OTP." }); }
  if (stored.code !== String(code).trim()) return res.status(400).json({ error: "Incorrect OTP. "+(5-stored.attempts)+" attempts left." });
  otpStore.delete(type+":"+destination);
  res.json({ success: true });
});

app.post("/gst/fetch", async (req, res) => {
  const { gstin } = req.body;
  if (!gstin || gstin.length !== 15) return res.status(400).json({ error: "Valid 15-character GSTIN required" });
  if (!process.env.GST_API_KEY) return res.status(503).json({ error: "GST API not configured. Add GST_API_KEY to environment variables." });
  try {
    const response = await fetch("https://api.mastersindia.co/mastersindia/gstin/"+gstin, {
      headers: { "Authorization": "Bearer "+process.env.GST_API_KEY, "client_id": process.env.GST_CLIENT_ID||"" }
    });
    if (!response.ok) { const e = await response.json().catch(()=>({})); throw new Error(e.message||"GST API error: "+response.status); }
    const data = await response.json();
    const addresses = [];
    if (data.pradr) { const a=data.pradr.addr; addresses.push({ id:"principal", type:"Principal Place of Business", line1:[a.bno,a.flno,a.bnm].filter(Boolean).join(", "), line2:[a.st,a.loc].filter(Boolean).join(", "), city:a.dst||"", state:a.stcd||"", pincode:a.pncd||"", isDefault:true }); }
    (data.adadr||[]).forEach((item,i) => { const a=item.addr; addresses.push({ id:"additional_"+(i+1), type:"Additional Place "+(i+1), line1:[a.bno,a.flno,a.bnm].filter(Boolean).join(", "), line2:[a.st,a.loc].filter(Boolean).join(", "), city:a.dst||"", state:a.stcd||"", pincode:a.pncd||"", isDefault:false }); });
    res.json({ gstin:data.gstin||gstin, legalName:data.lgnm||"", tradeName:data.tradeNam||"", status:data.sts||"Active", addresses, returns:[] });
  } catch(err) { console.error("[GST]",err.message); res.status(500).json({ error: err.message||"GST lookup failed" }); }
});

app.post("/compliance/check", async (req, res) => {
  const { fileBase64, mimeType, slotKey, clientKyc={} } = req.body;
  if (!fileBase64||!slotKey) return res.status(400).json({ error: "fileBase64 and slotKey required" });
  if (!process.env.ANTHROPIC_API_KEY) return res.status(503).json({ error: "Compliance API not configured. Add ANTHROPIC_API_KEY." });
  const pan=clientKyc.pan||"(not provided)", gst=clientKyc.gst||"(not provided)", biz=clientKyc.businessName||"";
  const prompts = {
    invoice: "You are a GST compliance officer in India. Check this invoice PDF:\n1. Supplier GSTIN present and matches: "+gst+"\n2. Buyer GSTIN present\n3. Supplier PAN matches: "+pan+"\n4. Invoice number and date present\n5. HSN/SAC codes on ALL line items\n6. CGST/SGST/IGST amounts present and consistent\n7. Supplier name matches: "+biz+"\nRespond ONLY with JSON: {\"passed\":true/false,\"errors\":[],\"warnings\":[]}",
    einvoice: "Check this e-Invoice PDF: 1.IRN (64 hex chars) present 2.QR code present 3.Supplier GSTIN matches: "+gst+" 4.Standard invoice fields. Respond ONLY JSON: {\"passed\":true/false,\"errors\":[],\"warnings\":[]}",
    eway: "Check E-Way Bill: 1.E-Way Bill number (12 digits) 2.Validity date 3.Vehicle/transporter ID 4.Consignor GSTIN matches: "+gst+" 5.HSN and taxable value. Respond ONLY JSON: {\"passed\":true/false,\"errors\":[],\"warnings\":[]}",
    imei: "Check IMEI list document: 1.Readable 2.IMEI numbers visible (15 digits each) 3.No obvious duplicates 4.Quantity countable. Respond ONLY JSON: {\"passed\":true/false,\"errors\":[],\"warnings\":[]}",
    docket: "Check courier docket/AWB: 1.AWB number legible 2.Sender/receiver details present 3.Courier name visible 4.Date present. Respond ONLY JSON: {\"passed\":true/false,\"errors\":[],\"warnings\":[]}"
  };
  try {
    const Anthropic = require("@anthropic-ai/sdk");
    const anthropic = new Anthropic.default({ apiKey: process.env.ANTHROPIC_API_KEY });
    const response = await anthropic.messages.create({ model:"claude-opus-4-5", max_tokens:500, messages:[{ role:"user", content:[{ type:"document", source:{ type:"base64", media_type:mimeType||"application/pdf", data:fileBase64 }},{ type:"text", text:prompts[slotKey]||prompts.invoice }]}]});
    const text = response.content.find(b=>b.type==="text")?.text||"{}";
    const result = JSON.parse(text.replace(/```json|```/g,"").trim());
    res.json({ passed:Boolean(result.passed), errors:Array.isArray(result.errors)?result.errors:[], warnings:Array.isArray(result.warnings)?result.warnings:[] });
  } catch(err) { console.error("[Compliance]",err.message); res.status(500).json({ error:"Compliance check failed: "+err.message }); }
});

async function sendSMS(phoneE164, code) {
  if (!process.env.TWILIO_ACCOUNT_SID) throw new Error("Twilio not configured. Add TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN.");
  const twilio = require("twilio");
  const client = twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
  await client.messages.create({ body:"Your KYC Verify OTP is: "+code+"\nValid 10 minutes. Do not share.", from:process.env.TWILIO_FROM_NUMBER, to:phoneE164 });
}

async function sendEmail(toEmail, code) {
  if (!process.env.BREVO_API_KEY) throw new Error("Brevo not configured. Add BREVO_API_KEY.");
  const response = await fetch("https://api.brevo.com/v3/smtp/email", {
    method:"POST", headers:{ "api-key":process.env.BREVO_API_KEY, "Content-Type":"application/json" },
    body: JSON.stringify({ sender:{ name:process.env.BREVO_FROM_NAME||"KYC Verify", email:process.env.BREVO_FROM_EMAIL }, to:[{ email:toEmail }], subject:"Your OTP: "+code+" - KYC Verify", htmlContent:"<div style='font-family:sans-serif;max-width:480px;margin:auto;padding:32px;border:1px solid #E2E8F0;border-radius:16px'><h2 style='color:#0F172A'>KYC Verify - OTP</h2><div style='font-size:42px;font-weight:800;letter-spacing:12px;color:#0284C7;background:#F1F5F9;padding:24px;border-radius:12px;text-align:center'>"+code+"</div><p style='color:#94A3B8;margin-top:16px'>Valid for 10 minutes. Do not share.</p></div>" })
  });
  if (!response.ok) { const b=await response.json().catch(()=>({})); throw new Error(b.message||"Brevo error: "+response.status); }
}

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log("\n KYC Verify backend running on port "+PORT);
  console.log("   Twilio: "+(process.env.TWILIO_ACCOUNT_SID?"Configured":"NOT configured"));
  console.log("   Brevo:  "+(process.env.BREVO_API_KEY?"Configured":"NOT configured"));
  console.log("   GST:    "+(process.env.GST_API_KEY?"Configured":"NOT configured"));
  console.log("   Claude: "+(process.env.ANTHROPIC_API_KEY?"Configured":"NOT configured")+"\n");
});
