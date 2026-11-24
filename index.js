require('dotenv').config();
const crypto = require('node:crypto');

const express = require('express');
const { deflateRawSync, inflateRawSync } = require('node:zlib');
const {
  Client,
  GatewayIntentBits,
  Partials,
  EmbedBuilder,
  AttachmentBuilder,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  ChannelType,
  PermissionFlagsBits
} = require('discord.js');

const app = express();
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('Referrer-Policy', 'no-referrer');
  res.set('X-Frame-Options', 'DENY');
  next();
});
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));

const token = process.env.DISCORD_TOKEN;
const apiKey = process.env.API_KEY;
const websiteApi = (process.env.WEBSITE_API_URL || '').trim();
const discordClientId = process.env.DISCORD_CLIENT_ID;
const discordClientSecret = process.env.DISCORD_CLIENT_SECRET;
const publicBaseUrl = (process.env.PUBLIC_BASE_URL || 'https://dibiaa.onrender.com').replace(/\/$/, '');
const discordRedirectUri =
  process.env.DISCORD_REDIRECT_URI ||
  'https://dibiaa.free.nf/discord-callback.php';

const ticketCategoryId = (process.env.TICKET_CATEGORY_ID || '').trim();
const supportRoleId = (process.env.SUPPORT_ROLE_ID || '').trim();

const requiredEnvironment = ['DISCORD_TOKEN', 'API_KEY', 'DISCORD_CLIENT_ID',
  'DISCORD_CLIENT_SECRET', 'DISCORD_REDIRECT_URI', 'PUBLIC_BASE_URL'];
const missingEnvironment = requiredEnvironment.filter(name => !String(process.env[name] || '').trim());
if (missingEnvironment.length) {
  console.error('Missing required environment variables: ' + missingEnvironment.join(', '));
  process.exit(1);
}
if (!/^https:\/\//i.test(publicBaseUrl) || !/^https:\/\//i.test(discordRedirectUri)) {
  console.error('PUBLIC_BASE_URL and DISCORD_REDIRECT_URI must use HTTPS.');
  process.exit(1);
}


// InfinityFree's free-hosting browser challenge blocks non-browser API requests.
// Keep panel data in memory when the website asks the bot to publish a panel.
const panelCache = new Map();
const ticketCooldowns = new Map();
const recentEvents = [];
function recordEvent(action, guildId, actorId = '', actorName = 'Discord', entityType = 'discord', entityId = '', details = {}) {
  recentEvents.unshift({ event_id: crypto.randomUUID(), guild_id: String(guildId || ''), actor_id: String(actorId || ''), actor_name: String(actorName || 'Discord'), action, entity_type: entityType, entity_id: String(entityId || ''), details, created_at: new Date().toISOString() });
  if (recentEvents.length > 500) recentEvents.length = 500;
}

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMembers],
  partials: [Partials.Channel]
});

function authorized(req) {
  return Boolean(apiKey && req.get('X-API-Key') === apiKey);
}

function looksLikeSecurityChallenge(body) {
  const text = String(body || '').toLowerCase();
  return text.includes('/aes.js') ||
    text.includes('this site requires javascript') ||
    text.includes('__test');
}

async function saveToWebsite(data) {
  if (!websiteApi) throw new Error('WEBSITE_API_URL missing');
  if (!apiKey) throw new Error('API_KEY missing');

  const response = await fetch(websiteApi, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Accept': 'application/json',
      'X-API-Key': apiKey
    },
    body: JSON.stringify(data),
    signal: AbortSignal.timeout(25000)
  });

  const body = await response.text();
  let result = {};
  try {
    result = JSON.parse(body);
  } catch {
    // A security challenge is HTML, not a JSON API response.
  }

  if (looksLikeSecurityChallenge(body)) {
    throw new Error(
      'InfinityFree security challenge blocked the Render API request. ' +
      'The request returned /aes.js HTML instead of JSON.'
    );
  }

  if (!response.ok || !result.ok) {
    throw new Error(
      `Website API failed (HTTP ${response.status}): ` +
      `${result.error || body.slice(0, 180) || 'Empty response'}`
    );
  }
  return result;
}

app.get('/', (req, res) => {
  res.json({
    ok: true,
    service: 'Dibiaa Hub Discord Bot',
    botReady: client.isReady(),
    cachedPanels: panelCache.size
  });
});

app.get('/events', (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildIds = String(req.query.guild_ids || '').split(',').filter(id => /^\d{15,22}$/.test(id));
  const events = guildIds.length ? recentEvents.filter(ev => guildIds.includes(ev.guild_id)) : [];
  return res.json({ ok: true, events: events.slice(0, 300) });
});


function signFormToken(payload) {
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const signature = crypto.createHmac('sha256', apiKey || 'missing-api-key').update(encoded).digest('base64url');
  return `${encoded}.${signature}`;
}
function verifyFormToken(token) {
  if (typeof token !== 'string' || token.length > 4096) return null;
  const parts = token.split('.');
  if (parts.length !== 2) return null;
  const expected = crypto.createHmac('sha256', apiKey || 'missing-api-key').update(parts[0]).digest();
  let actual;
  try { actual = Buffer.from(parts[1], 'base64url'); } catch { return null; }
  if (actual.length !== expected.length || !crypto.timingSafeEqual(actual, expected)) return null;
  try {
    const data = JSON.parse(Buffer.from(parts[0], 'base64url').toString('utf8'));
    if (!data || Date.now() > Number(data.exp || 0) || Date.now() - Number(data.iat || 0) > 60 * 60 * 1000) return null;
    return data;
  } catch { return null; }
}
const hiddenTagBase = 0xE0100;
function encodeHiddenTag(value) {
  return [...String(value)].map(char => String.fromCodePoint(hiddenTagBase + char.charCodeAt(0))).join('');
}
function decodeHiddenTag(value) {
  let decoded = '';
  for (const char of Array.from(String(value || ''))) {
    const cp = char.codePointAt(0) - hiddenTagBase;
    if (cp < 0 || cp > 127) continue;
    decoded += String.fromCharCode(cp);
  }
  return decoded;
}
function htmlEscape(value) {
  return String(value ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
}
const usedFormTokens = new Set();
async function recoverPanelFromMessage(data) {
  let panel = panelCache.get(String(data.panel_id));
  if (panel && Array.isArray(panel.form_fields) && panel.form_fields.length) return panel;
  const guild = await client.guilds.fetch(String(data.guild_id));
  const channel = await guild.channels.fetch(String(data.channel_id));
  const message = await channel.messages.fetch(String(data.message_id));
  const footer = message.embeds?.[0]?.footer?.text || '';
  panel = hydratePanelData(decodePanelFooter(footer), message.embeds?.[0]);
  if (!panel) throw new Error('Panel form data is unavailable. Ask an admin to republish the panel.');
  if (String(panel.id) !== String(data.panel_id)) throw new Error('Panel token does not match.');
  panelCache.set(String(panel.id), panel);
  return panel;
}


// Panel sequence is stored in the published panel message footer, so it survives
// Render restarts and remains independent for every panel.
const panelCounterLocks = new Map();
const ticketMetaCache = new Map();
function compactPanelData(panel) {
  const fields = Array.isArray(panel.form_fields) ? panel.form_fields.map(field => {
    const cfg = { ...(field.config || {}) };
    for (const [key, value] of Object.entries({ options: [], min: null, max: null, step: 1, min_length: 0,
      max_length: 1000, min_date: '', max_date: '', default: '', multiple: false, accept: '',
      max_size_mb: 5, min_rating: 1, max_rating: 5 })) {
      if (JSON.stringify(cfg[key]) === JSON.stringify(value)) delete cfg[key];
    }
    return [String(field.id || ''), String(field.type || 'text'), String(field.label || ''),
      String(field.help_text || ''), String(field.placeholder || ''), field.required === false ? 0 : 1, cfg];
  }) : [];
  const data = {
    v: 2, i: String(panel.id || ''), g: String(panel.guild_id || ''), o: String(panel.owner_discord_id || ''),
    f: fields, s: panel.settings || {}, n: Math.max(0, Number(panel.ticket_sequence || 0))
  };
  if (!fields.length) data.q = Array.isArray(panel.questions) ? panel.questions : [];
  return data;
}
function encodePanelData(panel) {
  const bytes = deflateRawSync(Buffer.from(JSON.stringify(compactPanelData(panel))), { level: 9 });
  return [...bytes].map(byte => String.fromCodePoint(0xFE00 + (byte >> 4), 0xFE00 + (byte & 15))).join('');
}
function hydratePanelData(stored, embed = null) {
  if (!stored || typeof stored !== 'object') return null;
  if (stored?.v === 2) {
    const fields = Array.isArray(stored.f) ? stored.f.map(row => ({
      id: row[0], type: row[1], label: row[2], help_text: row[3], placeholder: row[4],
      required: row[5] !== 0, config: row[6] || {}
    })) : [];
    stored = {
      id: stored.i, guild_id: stored.g, owner_discord_id: stored.o,
      form_fields: fields, settings: stored.s || {}, ticket_sequence: stored.n || 0,
      questions: Array.isArray(stored.q) ? stored.q : []
    };
  }
  if (embed) {
    stored.title = stored.title || embed.title || 'Support Ticket';
    stored.description = stored.description || embed.description || '';
  }
  if (!Array.isArray(stored.questions) || !stored.questions.length) {
    stored.questions = (stored.form_fields || []).filter(field => field.type !== 'static')
      .slice(0, 5).map(field => String(field.label || 'Question'));
  }
  return stored;
}
function panelFooter(panel) {
  const footer = 'Dibiaa Hub • Ticket Panel • ' + encodePanelData(panel);
  if (footer.length > 2048) throw new Error('Panel configuration is too large to store safely in the Discord panel message.');
  return footer;
}
function decodePanelFooter(footer) {
  const nibbleValues = [...String(footer || '')].map(char => char.codePointAt(0) - 0xFE00).filter(value => value >= 0 && value <= 15);
  if (nibbleValues.length >= 2 && nibbleValues.length % 2 === 0) {
    try {
      const bytes = Buffer.alloc(nibbleValues.length / 2);
      for (let i = 0; i < nibbleValues.length; i += 2) bytes[i / 2] = (nibbleValues[i] << 4) | nibbleValues[i + 1];
      return hydratePanelData(JSON.parse(inflateRawSync(bytes).toString('utf8')));
    } catch {}
  }
  const hidden = decodeHiddenTag(footer || '');
  const legacy = String(footer || '').match(/DH1:([A-Za-z0-9_-]+)/)?.[1];
  const packed = hidden || legacy;
  if (!packed) return null;
  try { return hydratePanelData(JSON.parse(inflateRawSync(Buffer.from(packed, 'base64url')).toString('utf8'))); }
  catch { return null; }
}
async function updatePanelMessage(panel, message) {
  if (!message || !message.embeds?.length) return false;
  const embed = EmbedBuilder.from(message.embeds[0]).setFooter({ text: panelFooter(panel) });
  await message.edit({ embeds: [embed] });
  panelCache.set(String(panel.id), panel);
  return true;
}
function panelPrefix(title) {
  const words = String(title || 'ticket').toLowerCase().normalize('NFKD')
    .replace(/[^a-z0-9\s-]/g, ' ').trim().split(/[\s-]+/).filter(Boolean);
  while (words.length > 1 && ['ticket','tickets','panel','form'].includes(words[words.length - 1])) words.pop();
  const prefix = words.length > 1
    ? words.map(word => word[0]).join('').slice(0, 8)
    : (words[0] || 'ticket').slice(0, 12);
  return prefix || 'ticket';
}
function supportRoleIds(panel, meta = {}) {
  const raw = [
    ...(Array.isArray(panel?.settings?.support_role_ids) ? panel.settings.support_role_ids : []),
    panel?.settings?.support_role_id,
    ...(Array.isArray(meta.support_role_ids) ? meta.support_role_ids : []),
    meta.support_role_id
  ];
  return [...new Set(raw.map(v => String(v || '').trim()).filter(v => /^\d{15,22}$/.test(v)))];
}
async function allocatePanelTicketNumber(panel, guild, panelMessage) {
  const key = String(panel.id);
  const previous = panelCounterLocks.get(key) || Promise.resolve();
  let release;
  const current = new Promise(resolve => { release = resolve; });
  const queued = previous.then(() => current);
  panelCounterLocks.set(key, queued);
  await previous.catch(() => {});
  try {
    // Do not derive the number from currently open channels: closed channels are
    // deleted, and each panel must keep its own independent sequence.
    const next = Math.max(0, Number(panel.ticket_sequence || 0)) + 1;
    const prefix = panelPrefix(panel.title);
    const name = `${prefix}-${next}`;
    panel.ticket_sequence = next;
    await updatePanelMessage(panel, panelMessage);
    return { number: next, name };
  } finally {
    release();
    if (panelCounterLocks.get(key) === queued) panelCounterLocks.delete(key);
  }
}
function encodeTicketMeta(meta) {
  const raw = Buffer.from(JSON.stringify({ _type: 'dibiaa_ticket', ...meta })).toString('base64url');
  return encodeHiddenTag(raw);
}
function decodeTicketMeta(footer) {
  const hidden = decodeHiddenTag(footer || '');
  if (!hidden) return null;
  try {
    const parsed = JSON.parse(Buffer.from(hidden, 'base64url').toString('utf8'));
    return parsed?._type === 'dibiaa_ticket' ? parsed : null;
  } catch { return null; }
}
function legacyTicketMeta(channel) {
  const topic = String(channel?.topic || '');
  const get = (re) => topic.match(re)?.[1] || '';
  if (!topic.includes('Dibiaa ticket |') && !get(/Owner ID:\s*(\d+)/)) return null;
  return {
    _type: 'dibiaa_ticket', owner_discord_id: get(/Owner ID:\s*(\d+)/),
    user_id: get(/User ID:\s*(\d+)/), user_name: get(/User Name:\s*([^|]+)/).trim(),
    panel_id: get(/Panel:\s*(\d+)/), support_role_ids: get(/Support Role IDs?:\s*([^|]+)/).split(',').map(x=>x.trim()).filter(Boolean),
    transcript_channel_id: get(/Transcript Channel ID:\s*(\d+)/),
    claimed_by: get(/Claimed By:\s*(\d+)/), claimed_name: get(/Claimed Name:\s*([^|]+)/).trim(),
    claim_message_id: get(/Claim Message ID:\s*(\d+)/)
  };
}
function maybeTicketChannel(channel) {
  const topic = String(channel?.topic || '');
  return ticketMetaCache.has(String(channel?.id || '')) || /Ticket #\d+/i.test(topic) || topic.includes('Dibiaa ticket |');
}
async function getTicketMeta(channel) {
  if (!channel) return null;
  const cached = ticketMetaCache.get(String(channel.id));
  if (cached) return cached;
  const legacy = legacyTicketMeta(channel);
  if (legacy) { ticketMetaCache.set(String(channel.id), legacy); return legacy; }
  try {
    const messages = await channel.messages.fetch({ limit: 30 });
    const botMessage = messages.find(m => m.author?.id === client.user?.id && m.embeds?.length && decodeTicketMeta(m.embeds[0]?.footer?.text));
    if (botMessage) {
      const meta = decodeTicketMeta(botMessage.embeds[0].footer.text);
      ticketMetaCache.set(String(channel.id), meta);
      return meta;
    }
  } catch (error) { console.warn('Ticket metadata read failed:', channel.id, error.message); }
  return null;
}
async function setTicketMeta(channel, meta, message = null) {
  ticketMetaCache.set(String(channel.id), meta);
  let target = message;
  if (!target) {
    const messages = await channel.messages.fetch({ limit: 30 });
    target = messages.find(m => m.author?.id === client.user?.id && m.embeds?.length);
  }
  if (!target?.embeds?.length) return false;
  const embed = EmbedBuilder.from(target.embeds[0]).setFooter({ text: encodeTicketMeta(meta) });
  await target.edit({ embeds: [embed] });
  return true;
}
async function getPanelMessage(panel, guild) {
  const channelId = String(panel.channel_id || '');
  const messageId = String(panel.message_id || '');
  if (!/^\d{15,22}$/.test(channelId) || !/^\d{15,22}$/.test(messageId)) return null;
  const channel = await guild.channels.fetch(channelId).catch(() => null);
  if (!channel?.isTextBased()) return null;
  return channel.messages.fetch(messageId).catch(() => null);
}
function webControl(field) {
  const c = field.config || {}, id = htmlEscape(field.id), label = htmlEscape(field.label), placeholder = htmlEscape(field.placeholder || '');
  const required = field.required && field.type !== 'static' ? ' required' : '';
  const opts = Array.isArray(c.options) ? c.options : [];
  if (field.type === 'static') return `<div class="static">${htmlEscape(c.default || field.help_text || label)}</div>`;
  if (['select','user-select','role-select','mentionable-select','channel-select'].includes(field.type)) {
    return `<select name="answers[${id}]"${required}><option value="">${placeholder || 'Choose an option'}</option>${opts.map(o=>`<option value="${htmlEscape(typeof o==='string'?o:o.value||o.label)}">${htmlEscape(typeof o==='string'?o:o.label)}</option>`).join('')}</select>`;
  }
  if (field.type === 'multi-select' || field.type === 'checkbox-group') return `<div class="options">${opts.map(o=>`<label><input type="checkbox" name="answers[${id}][]" value="${htmlEscape(typeof o==='string'?o:o.value||o.label)}"> ${htmlEscape(typeof o==='string'?o:o.label)}</label>`).join('')}</div>`;
  if (field.type === 'radio' || field.type === 'yes-no') {
    const choices = field.type === 'yes-no' ? ['Yes','No'] : opts.map(o=>typeof o==='string'?o:o.label);
    return `<div class="options">${choices.map(o=>`<label><input type="radio" name="answers[${id}]" value="${htmlEscape(o)}"${required}> ${htmlEscape(o)}</label>`).join('')}</div>`;
  }
  if (field.type === 'checkbox' || field.type === 'toggle') return `<label class="check"><input type="checkbox" name="answers[${id}]" value="Yes"> ${field.type==='toggle'?'Enable':'Yes'}</label>`;
  if (field.type === 'file' || field.type === 'image') return `<input type="text" name="answers[${id}]" placeholder="File uploads are not enabled on this deployment" disabled><small>Upload storage is not configured. Please describe the file in another field.</small>`;
  if (field.type === 'date-range') return `<div class="two"><input type="date" name="answers[${id}][start]"${required}><input type="date" name="answers[${id}][end]"${required}></div>`;
  if (field.type === 'rating') return `<input type="number" name="answers[${id}]" min="${Number(c.min_rating||1)}" max="${Number(c.max_rating||5)}"${required}>`;
  if (field.type === 'year') return `<input type="number" name="answers[${id}]" min="1900" max="2200" placeholder="YYYY"${required}>`;
  const allowed = ['text','textarea','number','email','password','tel','url','search','date','time','datetime-local','month','color'];
  if (field.type === 'textarea') return `<textarea name="answers[${id}]" placeholder="${placeholder}" maxlength="${Number(c.max_length||1000)}"${required}></textarea>`;
  const type = allowed.includes(field.type) ? field.type : 'text';
  return `<input type="${type}" name="answers[${id}]" placeholder="${placeholder}" value="${htmlEscape(c.default||'')}" ${type==='number'?`min="${htmlEscape(c.min??'')}" max="${htmlEscape(c.max??'')}" step="${htmlEscape(c.step||1)}"`:''} ${type==='date'||type==='time'||type==='datetime-local'||type==='month'?`min="${htmlEscape(c.min_date||'')}" max="${htmlEscape(c.max_date||'')}"`:''}${required}>`;
}
app.get('/ticket-form/:token', async (req, res) => {
  const data = verifyFormToken(req.params.token);
  if (!data || !/^\d{15,22}$/.test(String(data.user_id||''))) return res.status(400).send('This ticket form link is invalid or expired. Please click the Discord panel again.');
  try {
    const panel = await recoverPanelFromMessage(data);
    panel.channel_id = String(data.channel_id || panel.channel_id || ''); panel.message_id = String(data.message_id || panel.message_id || '');
    if (panel.settings?.enabled === 0) return res.status(403).send('This ticket panel is disabled.');
    const fields = Array.isArray(panel.form_fields) ? panel.form_fields : [];
    if (!fields.length) return res.status(400).send('No form fields are configured. Please ask an admin to edit the panel.');
    const uploadWarning = fields.some(f => ['file','image'].includes(f.type)) ? '<div class="upload-warning">File upload storage is not configured for this deployment. Upload fields are disabled; please describe the file instead.</div>' : '';
    const controls = fields.map((f,i)=>`<label class="field"><span>${htmlEscape(f.label||`Question ${i+1}`)}${f.required&&f.type!=='static'?' *':''}</span>${f.help_text?`<small>${htmlEscape(f.help_text)}</small>`:''}${webControl(f)}</label>`).join('');
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(panel.title)} · Dibiaa</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@400;500;600;700;800&display=swap" rel="stylesheet"><style>*{box-sizing:border-box}body{margin:0;background:#FFFFFF;color:#263A2B;font:15px/1.6 "DM Sans",Arial,sans-serif}.wrap{max-width:760px;margin:35px auto;padding:20px}.card{background:#fff;border:1px solid #E1E9DC;border-radius:18px;padding:28px;box-shadow:0 12px 35px rgba(38,58,43,.06)}h1{margin:0 0 8px;font-size:clamp(1.65rem,5vw,1.95rem);background:linear-gradient(100deg,#78C841 0%,#78C841 78%,#B4E50D 100%);background-clip:text;-webkit-background-clip:text;color:transparent}p{color:#65745F}.field{display:grid;gap:8px;margin:20px 0}.field>span{font-weight:600}.field small{color:#65745F}input,textarea,select{font:inherit;width:100%;padding:11px 12px;border:1px solid #E1E9DC;border-radius:9px;background:white;color:#263A2B}.options{display:grid;gap:9px}.options label,.check{display:flex;gap:9px;align-items:center}.options input,.check input{width:auto}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.static{padding:12px;background:#F7FAF5;border-radius:8px}.upload-warning{background:#FFF3E5;color:#9A580D;padding:12px;border-radius:8px}.btn{background:#B4E50D;color:#263A2B;border:0;border-radius:10px;padding:12px 18px;font:inherit;cursor:pointer;width:100%;margin-top:8px}@media(max-width:600px){.wrap{margin:10px auto;padding:10px}.card{padding:18px}.two{grid-template-columns:1fr}}</style></head><body><main class="wrap"><section class="card"><p>DIBIAA HUB · SUPPORT</p><h1>${htmlEscape(panel.title)}</h1><p>${htmlEscape(panel.description||'Please complete this form to open a ticket.')}</p><form method="post" action="/ticket-form/${htmlEscape(req.params.token)}">${uploadWarning}${controls}<button class="btn" type="submit">Submit and Open Ticket</button></form></section></main></body></html>`);
  } catch (error) {
    console.error('Ticket form load failed:', error.message);
    return res.status(502).send('Could not load this ticket form. Please return to Discord and try again.');
  }
});
app.post('/ticket-form/:token', async (req, res) => {
  const data = verifyFormToken(req.params.token);
  if (!data || usedFormTokens.has(req.params.token)) return res.status(400).send('This form link is invalid, expired, or already used. Please open the Discord panel again.');
  try {
    const panel = await recoverPanelFromMessage(data);
    panel.channel_id = String(data.channel_id || panel.channel_id || ''); panel.message_id = String(data.message_id || panel.message_id || '');
    const fields = Array.isArray(panel.form_fields) ? panel.form_fields : [];
    const inputAnswers = req.body?.answers && typeof req.body.answers === 'object' ? req.body.answers : {};
    const answers = [];
    for (const field of fields) {
      if (field.type === 'static') continue;
      const raw = inputAnswers[field.id];
      const value = Array.isArray(raw) ? raw.join(', ') : (raw && typeof raw === 'object' ? `${raw.start||''} to ${raw.end||''}` : String(raw ?? '').trim());
      if (field.required && !value && !['file','image'].includes(field.type)) return res.status(422).send(`Required field missing: ${htmlEscape(field.label)}. Go back and complete it.`);
      if (value && field.type === 'email' && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value)) return res.status(422).send(`Please enter a valid email for ${htmlEscape(field.label)}.`);
      if (value && field.type === 'url') { try { const u = new URL(value); if (!['http:','https:'].includes(u.protocol)) throw new Error(); } catch { return res.status(422).send(`Please enter a valid URL for ${htmlEscape(field.label)}.`); } }
      if (value) answers.push(`**${String(field.label||'Question').slice(0,200)}**\n${field.type === 'password' ? '[redacted for security; do not collect passwords in support forms]' : value.slice(0,3000)}`);
    }
    const guild = await client.guilds.fetch(String(data.guild_id));
    const member = await guild.members.fetch(String(data.user_id));
    const answerText = answers.join('\n\n') || 'No answers provided.';
    const panelMessage = await getPanelMessage(panel, guild);
    const ticketChannel = await createTicketChannel({ guild, user: member.user, panel, description: answerText, panelMessage });
    usedFormTokens.add(req.params.token);
    try { await saveToWebsite({action:'ticket_create',title:String(panel.title||'Support Ticket'),panel_id:Number(panel.id),panel_title:String(panel.title||''),ticket_number:Number(ticketMetaCache.get(String(ticketChannel.id))?.ticket_number||0),description:answerText,discord_user_id:member.id,user_name:member.user.username,discord_channel_id:ticketChannel.id,guild_id:guild.id,owner_discord_id:panel.owner_discord_id}); } catch (error) { console.error('Web form ticket DB sync failed:',error.message); }
    return res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ticket opened</title><style>body{font:18px/1.6 "DM Sans",Arial,sans-serif;background:#FFFFFF;color:#263A2B;padding:24px}.card{max-width:600px;margin:8vh auto;background:#fff;padding:28px;border-radius:16px}a{color:#4B8F24}h1{color:#4B8F24}</style></head><body><main class="card"><h1>Ticket opened successfully</h1><p>Your ticket channel is <a href="https://discord.com/channels/${guild.id}/${ticketChannel.id}">#${htmlEscape(ticketChannel.name)}</a>.</p><p>You can return to Discord now.</p></main></body></html>`);
  } catch (error) {
    console.error('Web form submission failed:',error.message);
    return res.status(502).send('Ticket could not be created. Please return to Discord and contact support.');
  }
});

// Ticket dashboard endpoint: PHP requests this from the browser-facing website,
// then stores the returned ticket rows in its own MySQL database.
app.get('/tickets/list', async (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  const guildId = String(req.query.guild_id || '');
  const ownerId = String(req.query.owner_discord_id || '');
  if (!/^\d{15,22}$/.test(ownerId)) return res.status(400).json({ ok: false, error: 'Valid owner_discord_id required' });
  if (!/^\d{15,22}$/.test(guildId)) {
    return res.status(400).json({ ok: false, error: 'Valid guild_id required' });
  }
  try {
    const guild = await client.guilds.fetch(guildId);
    const channels = await guild.channels.fetch();
    const tickets = [];
    for (const channel of channels.values()) {
      if (!channel || !channel.isTextBased() || !maybeTicketChannel(channel)) continue;
      const meta = await getTicketMeta(channel);
      if (!meta || String(meta.owner_discord_id || '') !== ownerId) continue;
      const userId = String(meta.user_id || '');
      if (!/^\d{15,22}$/.test(userId)) continue;
      let messageDescription = '';
      let embedTitle = channel.name || 'Discord Ticket';
      try {
        const messages = await channel.messages.fetch({ limit: 25 });
        const botMessage = messages.find(m => m.author.id === client.user.id && m.embeds.length);
        if (botMessage?.embeds?.[0]) {
          embedTitle = botMessage.embeds[0].title || embedTitle;
          messageDescription = botMessage.embeds[0].description || '';
        }
      } catch (err) { console.error('Ticket channel read failed:', channel.id, err.message); }
      let userName = String(meta.user_name || '');
      if (!userName) { try { userName = (await guild.members.fetch(userId)).user.username; } catch {} }
      tickets.push({
        title: embedTitle, user_name: userName, owner_discord_id: ownerId,
        description: messageDescription || 'Ticket created in Discord.',
        discord_user_id: userId, discord_channel_id: channel.id, guild_id: guildId,
        panel_id: Number(meta.panel_id || 0), panel_title: String(meta.panel_title || ''),
        ticket_number: Number(meta.ticket_number || 0),
        status: 'open', claimed_by: String(meta.claimed_by || ''),
        claimed_by_name: String(meta.claimed_name || ''),
        created_at: channel.createdAt.toISOString().slice(0, 19).replace('T', ' ')
      });
    }
    return res.json({ ok: true, tickets });
  } catch (error) {
    console.error('Ticket list error:', error.message);
    return res.status(500).json({ ok: false, error: 'Could not load tickets from Discord.' });
  }
});

app.get('/tickets/:channelId/transcript', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.query.guild_id || ''), ownerId = String(req.query.owner_discord_id || ''), channelId = String(req.params.channelId || '');
  if (!/^\d{15,22}$/.test(guildId) || !/^\d{15,22}$/.test(ownerId) || !/^\d{15,22}$/.test(channelId)) return res.status(400).json({ ok:false, error:'Valid guild, owner and channel IDs required' });
  try {
    const guild = await client.guilds.fetch(guildId); const channel = await guild.channels.fetch(channelId);
    const meta = await getTicketMeta(channel);
    if (!channel || !channel.isTextBased() || !meta || String(meta.owner_discord_id || '') !== ownerId) return res.status(404).json({ ok:false, error:'Ticket not found for this owner/server' });
    const collected = []; let before;
    for (let page=0; page<10; page++) {
      const batch = await channel.messages.fetch({ limit:100, ...(before ? {before} : {}) });
      if (!batch.size) break;
      collected.push(...batch.values()); before = batch.last().id;
      if (batch.size < 100 || collected.length >= 1000) break;
    }
    const messages = collected.slice(0,1000).sort((a,b)=>a.createdTimestamp-b.createdTimestamp).map(m=>({
      id:m.id, author_id:m.author.id, author_name:m.member?.displayName || m.author.globalName || m.author.username,
      author_avatar_url:m.author.displayAvatarURL({size:128}), content:m.content || '', type:String(m.type), is_bot:m.author.bot,
      created_at:m.createdAt.toISOString().slice(0,19).replace('T',' '), edited_at:m.editedAt ? m.editedAt.toISOString().slice(0,19).replace('T',' ') : null,
      attachments:[...m.attachments.values()].map(a=>({id:a.id,name:a.name,content_type:a.contentType,size:a.size,url:a.url}))
    }));
    return res.json({ok:true,guild_id:guildId,channel_id:channelId,messages});
  } catch (error) { console.error('Ticket transcript fetch failed:',error.message); return res.status(502).json({ok:false,error:'Could not fetch ticket transcript'}); }
});


// Live role list used by Staff & Teams and the panel builder.
app.get('/guilds/:guildId/roles', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.params.guildId || '');
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ ok: false, error: 'Valid guild ID required' });
  try {
    const guild = await client.guilds.fetch(guildId);
    const roles = await guild.roles.fetch();
    return res.json({
      ok: true,
      roles: [...roles.values()].filter(role => role && !role.managed && role.id !== guild.id)
        .map(role => ({ id: role.id, name: role.name, position: role.position }))
        .sort((a, b) => b.position - a.position)
    });
  } catch (error) {
    console.error('Guild role lookup failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not load Discord roles. Confirm the bot is in this server and has View Server/Manage Roles access.' });
  }
});

// Member listing requires the privileged Server Members Intent in the Discord Developer Portal.
app.get('/guilds/:guildId/members', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.params.guildId || '');
  const roleId = String(req.query.role_id || '');
  if (!/^\d{15,22}$/.test(guildId) || !/^\d{15,22}$/.test(roleId)) {
    return res.status(400).json({ ok: false, error: 'Valid guild ID and role_id are required.' });
  }
  try {
    const guild = await client.guilds.fetch(guildId);
    const role = await guild.roles.fetch(roleId);
    if (!role) return res.status(404).json({ ok: false, error: 'That Discord role no longer exists. Remove it from Staff & Teams and assign a current role.' });
    const members = await guild.members.fetch();
    const matching = [...members.values()].filter(member => member.roles.cache.has(roleId));
    return res.json({
      ok: true,
      members: matching.map(member => ({
        id: member.id,
        username: member.user.username,
        display_name: member.displayName || member.user.globalName || member.user.username,
        avatar: member.displayAvatarURL({ size: 64 }),
        roles: [...member.roles.cache.values()].filter(r => r.id !== guild.id).map(r => ({ id: r.id, name: r.name }))
      }))
    });
  } catch (error) {
    console.error('Guild member lookup failed:', error.message);
    const intentHint = /intent|privileged|members/i.test(error.message)
      ? ' Enable Server Members Intent in Discord Developer Portal > Bot, then restart/redeploy the bot.'
      : ' Confirm the bot is in this server and can access its member list.';
    return res.status(502).json({ ok: false, error: 'Discord could not return the server member list.' + intentHint });
  }
});

app.get('/guilds/:guildId/status', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.params.guildId || '');
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ ok: false, error: 'Valid guild ID required' });
  try {
    const guild = await client.guilds.fetch(guildId);
    const channels = await guild.channels.fetch().catch(() => new Map());
    return res.json({
      ok: true, bot_installed: true, guild_id: guild.id, guild_name: guild.name,
      icon: guild.iconURL({ size: 128 }), channels_count: channels.size,
      cached_panels: [...panelCache.values()].filter(p => String(p.guild_id) === guildId).length
    });
  } catch {
    return res.json({ ok: true, bot_installed: false, guild_id: guildId });
  }
});

// Channel and role choices for the panel builder. Data comes from the connected Discord server.
app.get('/guilds/:guildId/channels', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.params.guildId || '');
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ ok: false, error: 'Valid guild ID required' });
  try {
    const guild = await client.guilds.fetch(guildId);
    const [channels, roles] = await Promise.all([guild.channels.fetch(), guild.roles.fetch().catch(() => null)]);
    return res.json({
      ok: true,
      channels: [...channels.values()].filter(c => c && [ChannelType.GuildText, ChannelType.GuildAnnouncement, ChannelType.GuildCategory].includes(c.type)).map(c => ({ id: c.id, name: c.name, type: c.type, parent_id: c.parentId || null })),
      roles: roles ? [...roles.values()].filter(r => !r.managed && r.id !== guild.id).map(r => ({ id: r.id, name: r.name, position: r.position })).sort((a,b) => b.position-a.position) : []
    });
  } catch (error) {
    console.error('Guild channel lookup failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not load channels. Check bot membership and View Channels permission.' });
  }
});

// OAuth code exchange. The PHP callback must validate OAuth state first.
app.post('/oauth/discord/exchange', async (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }
  if (!discordClientId || !discordClientSecret) {
    return res.status(500).json({
      ok: false,
      error: 'Discord OAuth environment variables are missing'
    });
  }

  const code = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
  const redirectUri =
    typeof req.body?.redirect_uri === 'string'
      ? req.body.redirect_uri.trim()
      : '';

  if (!code || code.length > 2048) {
    return res.status(400).json({ ok: false, error: 'Missing or invalid authorization code' });
  }
  if (redirectUri !== discordRedirectUri) {
    return res.status(400).json({ ok: false, error: 'Invalid redirect URI' });
  }

  try {
    const form = new URLSearchParams({
      client_id: discordClientId,
      client_secret: discordClientSecret,
      grant_type: 'authorization_code',
      code,
      redirect_uri: discordRedirectUri
    });

    const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: form,
      signal: AbortSignal.timeout(15000)
    });
    const tokenData = await tokenResponse.json().catch(() => ({}));

    if (!tokenResponse.ok || !tokenData.access_token) {
      console.error('Discord OAuth token exchange failed. HTTP:', tokenResponse.status);
      return res.status(502).json({
        ok: false,
        error: 'Discord authorization failed. Please log in again.'
      });
    }

    const headers = { Authorization: `Bearer ${tokenData.access_token}` };
    const [userResponse, guildResponse] = await Promise.all([
      fetch('https://discord.com/api/v10/users/@me', {
        headers, signal: AbortSignal.timeout(15000)
      }),
      fetch('https://discord.com/api/v10/users/@me/guilds', {
        headers, signal: AbortSignal.timeout(15000)
      })
    ]);
    const user = await userResponse.json().catch(() => ({}));
    const guilds = await guildResponse.json().catch(() => []);

    if (!userResponse.ok || !user.id || !guildResponse.ok || !Array.isArray(guilds)) {
      return res.status(502).json({
        ok: false,
        error: 'Could not load Discord profile or servers'
      });
    }

    const manageableGuilds = guilds.filter(guild => {
      try {
        const permissions = BigInt(guild.permissions || '0');
        return guild.owner === true ||
          (permissions & 0x20n) !== 0n ||
          (permissions & 0x8n) !== 0n;
      } catch {
        return false;
      }
    }).map(guild => ({
      id: guild.id,
      name: guild.name,
      icon: guild.icon || null,
      owner: guild.owner === true,
      permissions: guild.permissions
    }));

    return res.json({
      ok: true,
      user: {
        id: user.id,
        username: user.username,
        global_name: user.global_name || null,
        avatar: user.avatar || null
      },
      guilds: manageableGuilds
    });
  } catch (error) {
    console.error('OAuth exchange error:', error.message);
    return res.status(502).json({
      ok: false,
      error: 'Could not contact Discord. Please try again.'
    });
  }
});

// Website calls this endpoint to publish a panel. Cache the panel's questions
// here so the Discord button does not need a Render -> InfinityFree API call.
app.post('/publish-panel', async (req, res) => {
  if (!authorized(req)) {
    return res.status(401).json({ ok: false, error: 'Unauthorized' });
  }

  try {
    const {
      panel_id, guild_id, channel_id, message_id, title, description, questions, settings = {}, owner_discord_id
    } = req.body || {};

    const id = String(panel_id || '');
    if (
      !/^\d+$/.test(id) ||
      !/^\d{15,22}$/.test(String(guild_id || '')) ||
      !/^\d{15,22}$/.test(String(channel_id || '')) || !/^\d{15,22}$/.test(String(owner_discord_id || '')) ||
      typeof title !== 'string' || !title.trim() ||
      !Array.isArray(questions) ||
      questions.length < 1 ||
      questions.length > 5 ||
      questions.some(q => typeof q !== 'string' || !q.trim())
    ) {
      return res.status(400).json({
        ok: false,
        error: 'Missing fields or invalid questions (1-5).'
      });
    }

    if (!client.isReady()) {
      return res.status(503).json({ ok: false, error: 'Discord bot is not ready yet.' });
    }

    const guild = await client.guilds.fetch(String(guild_id));
    const channel = await guild.channels.fetch(String(channel_id));
    let previousSequence = Number(panelCache.get(id)?.ticket_sequence || 0);
    if (typeof message_id === 'string' && /^\d{15,22}$/.test(message_id) && channel?.isTextBased()) {
      const oldMessage = await channel.messages.fetch(message_id).catch(() => null);
      const oldPanel = oldMessage?.embeds?.[0] ? decodePanelFooter(oldMessage.embeds[0].footer?.text || '') : null;
      if (oldPanel && String(oldPanel.id) === id) previousSequence = Math.max(previousSequence, Number(oldPanel.ticket_sequence || 0));
    }

    if (!channel || !channel.isTextBased() || !channel.send) {
      return res.status(400).json({
        ok: false,
        error: 'Channel not found or not a text channel.'
      });
    }

    const safeSettings = settings && typeof settings === 'object' ? settings : {};
    const safePanel = {
      id, guild_id: String(guild_id), owner_discord_id: String(owner_discord_id),
      title: String(title).slice(0, 256),
      description: String(description || 'Click below to open a ticket.').slice(0, 4000),
      questions: questions.map(q => String(q).trim().slice(0, 200)),
      form_fields: Array.isArray(req.body.form_fields) ? req.body.form_fields.slice(0, 40) : [],
      settings: safeSettings,
      ticket_sequence: previousSequence,
      channel_id: String(channel_id),
      message_id: typeof message_id === 'string' ? message_id : ''
    };
    const colourText = /^#[0-9a-fA-F]{6}$/.test(String(safeSettings.panel_colour || '')) ? String(safeSettings.panel_colour) : '#78C841';
    let footerText;
    try { footerText = panelFooter(safePanel); }
    catch {
      return res.status(413).json({ ok: false, error: 'This form is larger than Discord can store with the panel. Shorten long option lists or help text, then publish again.' });
    }
    // Discord caps the combined text in an embed at 6000 characters. The footer
    // carries the recoverable form configuration, so reserve that space first.
    const descriptionBudget = Math.max(0, 6000 - safePanel.title.length - footerText.length);
    safePanel.description = safePanel.description.slice(0, descriptionBudget);
    const embed = new EmbedBuilder()
      .setTitle(safePanel.title)
      .setColor(colourText)
      .setFooter({ text: footerText });
    if (safePanel.description) embed.setDescription(safePanel.description);
    if (/^https:\/\//i.test(String(safeSettings.thumbnail_url || ''))) embed.setThumbnail(String(safeSettings.thumbnail_url).slice(0, 500));
    if (/^https:\/\//i.test(String(safeSettings.image_url || ''))) embed.setImage(String(safeSettings.image_url).slice(0, 500));
    const styleMap = { Primary: ButtonStyle.Primary, Secondary: ButtonStyle.Secondary, Success: ButtonStyle.Success, Danger: ButtonStyle.Danger };
    const button = new ButtonBuilder().setCustomId('dh_open:' + id).setLabel(String(safeSettings.button_text || 'Open Ticket').slice(0, 80)).setStyle(styleMap[safeSettings.button_colour] || ButtonStyle.Danger);
    const emoji = String(safeSettings.button_emoji || '').trim();
    if (emoji && emoji.length <= 20) { try { button.setEmoji(emoji); } catch {} }
    const row = new ActionRowBuilder().addComponents(button);

    let message = null;
    if (typeof message_id === 'string' && /^\d{15,22}$/.test(message_id)) {
      try {
        const existingMessage = await channel.messages.fetch(message_id);
        message = await existingMessage.edit({ embeds: [embed], components: [row] });
      } catch (editError) {
        console.warn(`Existing panel message ${message_id} could not be edited; publishing a replacement.`);
      }
    }
    if (!message) message = await channel.send({ embeds: [embed], components: [row] });
    safePanel.channel_id = String(channel.id); safePanel.message_id = String(message.id);
    // Keep the published message reference in the cache for durable per-panel counters.
    panelCache.set(id, safePanel);
    recordEvent('panel_published', guild.id, '', 'Dibiaa Bot', 'panel', id, { channel_id: channel.id });

    // Avoid a Render -> InfinityFree request here; free-hosting challenges may return HTML.
    console.log(`Panel ${id} ${message.id === message_id ? 'updated' : 'published'}. Discord message: ${message.id}`);

    return res.json({
      ok: true,
      message_id: message.id,
      channel_id: channel.id,
      updated_existing: Boolean(message_id && message.id === message_id)
    });
  } catch (error) {
    console.error('Panel publish error:', error.message);
    return res.status(500).json({
      ok: false,
      error: error.message || 'Panel publish failed'
    });
  }
});

app.post('/panel-reset-counter', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const { panel_id, guild_id, channel_id, message_id, owner_discord_id } = req.body || {};
  if (!/^\d+$/.test(String(panel_id || '')) || !/^\d{15,22}$/.test(String(guild_id || '')) ||
      !/^\d{15,22}$/.test(String(channel_id || '')) || !/^\d{15,22}$/.test(String(message_id || '')) ||
      !/^\d{15,22}$/.test(String(owner_discord_id || ''))) {
    return res.status(400).json({ ok: false, error: 'Invalid panel reset request.' });
  }
  try {
    const guild = await client.guilds.fetch(String(guild_id));
    const channel = await guild.channels.fetch(String(channel_id));
    if (!channel?.isTextBased()) return res.status(404).json({ ok: false, error: 'Panel channel not found.' });
    const message = await channel.messages.fetch(String(message_id));
    const panel = hydratePanelData(decodePanelFooter(message.embeds?.[0]?.footer?.text || ''), message.embeds?.[0]);
    if (!panel || String(panel.id) !== String(panel_id) || String(panel.guild_id) !== String(guild_id) || String(panel.owner_discord_id) !== String(owner_discord_id)) {
      return res.status(403).json({ ok: false, error: 'Panel ownership could not be verified. Republish the panel and try again.' });
    }
    panel.ticket_sequence = 0;
    panel.channel_id = String(channel_id);
    panel.message_id = String(message_id);
    await updatePanelMessage(panel, message);
    recordEvent('panel_ticket_counter_reset', guild.id, String(owner_discord_id), 'Workspace owner', 'panel', String(panel_id));
    return res.json({ ok: true, next_ticket_number: 1 });
  } catch (error) {
    console.error('Panel ticket counter reset failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not reset the panel ticket counter.' });
  }
});

app.post('/panel-toggle', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const { panel_id, guild_id, channel_id, message_id, enabled, owner_discord_id } = req.body || {};
  if (!/^\d+$/.test(String(panel_id || '')) || !/^\d{15,22}$/.test(String(guild_id || '')) ||
      !/^\d{15,22}$/.test(String(channel_id || '')) || !/^\d{15,22}$/.test(String(message_id || '')) || !/^\d{15,22}$/.test(String(owner_discord_id || '')) ||
      typeof enabled !== 'boolean') {
    return res.status(400).json({ ok: false, error: 'Invalid panel toggle request.' });
  }
  try {
    const guild = await client.guilds.fetch(String(guild_id));
    const channel = await guild.channels.fetch(String(channel_id));
    if (!channel || !channel.isTextBased()) return res.status(404).json({ ok: false, error: 'Panel channel not found.' });
    const message = await channel.messages.fetch(String(message_id));
    const oldEmbed = message.embeds[0];
    const oldFooter = oldEmbed?.footer?.text || '';
    let panel = panelCache.get(String(panel_id));
    const storedPanel = decodePanelFooter(oldFooter);
    if (storedPanel) panel = hydratePanelData(storedPanel, oldEmbed);
    if (!panel || String(panel.owner_discord_id || '') !== String(owner_discord_id) || String(panel.guild_id || '') !== String(guild_id)) return res.status(404).json({ ok: false, error: 'Panel configuration could not be recovered for this owner/server.' });
    panel.settings = { ...(panel.settings || {}), enabled: enabled ? 1 : 0 };
    panel.channel_id = String(channel_id); panel.message_id = String(message_id);
    panelCache.set(String(panel_id), panel);
    const embed = oldEmbed ? EmbedBuilder.from(oldEmbed).setFooter({ text: panelFooter(panel) }) : null;
    const rows = message.components.map(row => {
      const actionRow = ActionRowBuilder.from(row);
      actionRow.setComponents(actionRow.components.map(component => {
        const b = ButtonBuilder.from(component);
        return b.setDisabled(!enabled);
      }));
      return actionRow;
    });
    await message.edit({ embeds: embed ? [embed] : [], components: rows });
    recordEvent(enabled ? 'panel_enabled' : 'panel_disabled', guild.id, '', 'Dibiaa Bot', 'panel', String(panel_id));
    return res.json({ ok: true, enabled });
  } catch (error) {
    console.error('Panel toggle failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not update the Discord panel message.' });
  }
});

async function createTicketChannel({ guild, user, panel, description, panelMessage = null }) {
  if (!guild || !user) throw new Error('Tickets can only be opened inside a server.');
  const roleIds = supportRoleIds(panel);
  await guild.roles.fetch().catch(() => null);
  const ticketNumber = await allocatePanelTicketNumber(panel, guild, panelMessage);
  const overwrites = [
    { id: guild.id, deny: [PermissionFlagsBits.ViewChannel] },
    { id: user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
      PermissionFlagsBits.ReadMessageHistory,
      ...(panel.settings?.permission_attachments === 0 ? [] : [PermissionFlagsBits.AttachFiles]),
      ...(panel.settings?.permission_embeds === 0 ? [] : [PermissionFlagsBits.EmbedLinks])] },
    { id: client.user.id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
      PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.ManageChannels,
      PermissionFlagsBits.EmbedLinks, PermissionFlagsBits.AttachFiles] }
  ];
  // Grant access to actual team members instead of role overwrites when practical.
  // This keeps role badges/role chips out of the ticket channel's member header.
  let supportMemberIds = [];
  let membersLoaded = false;
  if (roleIds.length) {
    const members = await guild.members.fetch().catch(() => null);
    if (members) { membersLoaded = true; supportMemberIds = [...members.values()]
      .filter(member => member.id !== user.id && member.id !== client.user.id && roleIds.some(roleId => member.roles.cache.has(roleId)))
      .map(member => member.id); }
  }
  if (membersLoaded && supportMemberIds.length <= 90) {
    for (const memberId of supportMemberIds) overwrites.push({ id: memberId, allow: [
      PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
      PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles,
      PermissionFlagsBits.EmbedLinks
    ] });
  } else {
    // Discord caps permission overwrites per channel. Large teams use role overwrites.
    for (const roleId of roleIds) if (guild.roles.cache.has(roleId)) overwrites.push({ id: roleId, allow: [
      PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages,
      PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles,
      PermissionFlagsBits.EmbedLinks
    ] });
  }
  const meta = {
    _type: 'dibiaa_ticket', owner_discord_id: String(panel.owner_discord_id || ''),
    guild_id: String(guild.id), user_id: String(user.id), user_name: String(user.username || 'user'),
    panel_id: String(panel.id), panel_title: String(panel.title || 'Support Ticket'),
    ticket_number: ticketNumber.number, support_role_ids: roleIds,
    transcript_channel_id: String(panel.settings?.transcript_channel_id || ''),
    close_on_user_leave: Boolean(panel.settings?.close_on_user_leave),
    claimed_by: '', claimed_name: '', claim_message_id: ''
  };
  const options = {
    name: ticketNumber.name, type: ChannelType.GuildText,
    topic: `${meta.panel_title.slice(0,90)} · Ticket #${ticketNumber.number} · Opened by ${String(user.username || 'user').slice(0,40)}`,
    permissionOverwrites: overwrites
  };
  const category = String(panel.settings?.ticket_category_id || ticketCategoryId || '');
  if (category && /^\d{15,22}$/.test(category)) options.parent = category;
  const channel = await guild.channels.create(options);
  ticketMetaCache.set(String(channel.id), meta);
  recordEvent('ticket_created', guild.id, user.id, user.username, 'ticket', channel.id,
    { owner_discord_id: meta.owner_discord_id, panel_id: meta.panel_id, ticket_number: ticketNumber.number });
  const embed = new EmbedBuilder()
    .setTitle(String(panel.title || 'Support Ticket').slice(0,256))
    .setDescription(String(description || 'No details provided.').slice(0,4000))
    .setColor(/^#[0-9a-fA-F]{6}$/.test(String(panel.settings?.panel_colour || '')) ? Number.parseInt(String(panel.settings.panel_colour).slice(1),16) : 0x78c841)
    .addFields({ name: 'Opened by', value: `<@${user.id}>`, inline: true },
      { name: 'Ticket ID', value: `#${ticketNumber.number}`, inline: true })
    .setFooter({ text: encodeTicketMeta(meta) }).setTimestamp();
  const buttons = [];
  if (!(panel.settings?.hide_close_button || panel.settings?.allow_user_close === 0)) {
    buttons.push(new ButtonBuilder().setCustomId('dh_close:' + channel.id).setLabel('Close Ticket').setEmoji('🔒').setStyle(ButtonStyle.Danger));
  }
  if (!panel.settings?.hide_claim_button) {
    buttons.push(new ButtonBuilder().setCustomId(`dh_claim:${channel.id}:${panel.id}`).setLabel('Claim Ticket').setEmoji('🙋').setStyle(ButtonStyle.Primary));
  }
  await channel.send({
    content: `<@${user.id}>`, embeds: [embed],
    components: buttons.length ? [new ActionRowBuilder().addComponents(buttons)] : [],
    allowedMentions: { users: [user.id], roles: [], parse: [] }
  });
  return channel;
}
async function createPrivateTicketChannel(interaction, panel, description) {
  const panelMessage = interaction.message || await getPanelMessage(panel, interaction.guild);
  return createTicketChannel({ guild: interaction.guild, user: interaction.user, panel, description, panelMessage });
}

function supportHoursMessage(panel) {
  const settings = panel?.settings || {};
  const enabledDays = Array.isArray(settings.support_hours) ? settings.support_hours : [];
  if (!enabledDays.length) return null; // no schedule configured = unrestricted
  const timezone = String(settings.support_timezone || 'Asia/Kolkata');
  let parts;
  try {
    parts = new Intl.DateTimeFormat('en-US', {
      timeZone: timezone, weekday: 'long', hour: '2-digit', minute: '2-digit', hourCycle: 'h23'
    }).formatToParts(new Date()).reduce((o, p) => (o[p.type] = p.value, o), {});
  } catch { return 'Support hours timezone is invalid. Please ask an admin to check the panel settings.'; }
  const day = parts.weekday;
  const nowMinutes = Number(parts.hour) * 60 + Number(parts.minute);
  const times = settings.support_hours_times || {};
  const current = times[day] || {};
  const parse = value => {
    const m = String(value || '').match(/^([01]\d|2[0-3]):([0-5]\d)$/);
    return m ? Number(m[1]) * 60 + Number(m[2]) : null;
  };
  if (enabledDays.includes(day)) {
    const start = parse(current.start), end = parse(current.end);
    if (start === null || end === null || start === end) return null;
    if (start < end && nowMinutes >= start && nowMinutes < end) return null;
    if (start > end && (nowMinutes >= start || nowMinutes < end)) return null;
  }
  const dayOrder = ['Sunday','Monday','Tuesday','Wednesday','Thursday','Friday','Saturday'];
  const prev = dayOrder[(dayOrder.indexOf(day) + 6) % 7];
  const prevTimes = times[prev] || {};
  const prevStart = parse(prevTimes.start), prevEnd = parse(prevTimes.end);
  if (enabledDays.includes(prev) && prevStart !== null && prevEnd !== null && prevStart > prevEnd && nowMinutes < prevEnd) return null;
  return `Support is currently unavailable. Supported days: ${enabledDays.join(', ')} (${timezone}).`;
}

client.on('interactionCreate', async interaction => {
  try {
    if (interaction.isButton() && interaction.customId.startsWith('dh_open:')) {
      const panelId = interaction.customId.slice('dh_open:'.length);
      let panel = panelCache.get(panelId);

      // Recover saved panel settings from the Discord message itself after a Render restart.
      if (!panel) {
        try {
          const message = await interaction.message.fetch();
          const footer = message.embeds?.[0]?.footer?.text || '';
          const recovered = hydratePanelData(decodePanelFooter(footer), message.embeds?.[0]);
          if (recovered) {
            if (String(recovered.id) === panelId && Array.isArray(recovered.questions)) {
              panel = recovered;
              panelCache.set(panelId, panel);
            }
          }
        } catch (error) {
          console.error('Panel recovery failed:', error.message);
        }
      }

      if (panel) { panel.channel_id = interaction.channelId; panel.message_id = interaction.message.id; panelCache.set(String(panel.id), panel); }
      if (panel && panel.settings && panel.settings.enabled === 0) { await interaction.reply({ content: 'This ticket panel is currently disabled.', ephemeral: true }); return; }
      if (!panel || !Array.isArray(panel.questions) ||
          panel.questions.length < 1 || panel.questions.length > 5) {
        await interaction.reply({
          content: 'This panel is not loaded by the bot. Please ask an admin to publish the panel again.',
          ephemeral: true
        });
        return;
      }

      const formFields = Array.isArray(panel.form_fields) ? panel.form_fields : [];
      const nativeModalTypes = new Set(['text', 'textarea']);
      const needsWebForm = formFields.length > 5 || formFields.some(f => !nativeModalTypes.has(String(f.type || 'text')));
      if (needsWebForm) {
        const token = signFormToken({
          panel_id: String(panel.id), user_id: interaction.user.id, owner_discord_id: String(panel.owner_discord_id || ''),
          guild_id: interaction.guildId, channel_id: interaction.channelId,
          message_id: interaction.message.id, iat: Date.now(), exp: Date.now() + 60 * 60 * 1000
        });
        await interaction.reply({
          content: `Please complete the secure ticket form here (link expires in 1 hour): ${publicBaseUrl}/ticket-form/${token}`,
          ephemeral: true
        });
        return;
      }

      const scheduleMessage = supportHoursMessage(panel);
      if (scheduleMessage) {
        await interaction.reply({ content: scheduleMessage, ephemeral: true });
        return;
      }
      const cooldownSeconds = Math.max(0, Number(panel.settings?.cooldown_seconds || 0));
      const cooldownKey = `${panelId}:${interaction.user.id}`;
      const lastOpened = ticketCooldowns.get(cooldownKey) || 0;
      const remaining = cooldownSeconds - Math.floor((Date.now() - lastOpened) / 1000);
      if (remaining > 0) {
        await interaction.reply({ content: `Please wait ${remaining} second(s) before opening another ticket.`, ephemeral: true });
        return;
      }
      const maxOpen = Math.max(0, Number(panel.settings?.max_open_tickets || 0));
      if (maxOpen > 0) {
        const channels = await interaction.guild.channels.fetch().catch(() => null);
        let openCount = 0;
        if (channels) for (const ch of channels.values()) {
          if (!ch || !ch.isTextBased() || !maybeTicketChannel(ch)) continue;
          const meta = await getTicketMeta(ch);
          if (meta && String(meta.user_id) === interaction.user.id && String(meta.panel_id) === String(panelId)) openCount++;
        }
        if (openCount >= maxOpen) {
          await interaction.reply({ content: `You already have ${openCount} open ticket(s) for this panel. Maximum allowed: ${maxOpen}.`, ephemeral: true });
          return;
        }
      }
      ticketCooldowns.set(cooldownKey, Date.now());

      const modal = new ModalBuilder()
        .setCustomId('dh_submit:' + panelId)
        .setTitle(String(panel.title || 'Support Ticket').slice(0, 45));

      panel.questions.forEach((question, index) => {
        const field = Array.isArray(panel.form_fields) ? panel.form_fields[index] : null;
        const q = String(field?.label || question || `Question ${index + 1}`);
        const input = new TextInputBuilder()
          .setCustomId('q' + index)
          .setLabel(q.slice(0, 45))
          .setStyle(field?.type === 'textarea' || q.length > 70 ? TextInputStyle.Paragraph : TextInputStyle.Short)
          .setRequired(field?.required !== false)
          .setMaxLength(Math.max(1, Math.min(4000, Number(field?.config?.max_length || 1000))));
        const placeholder = String(field?.placeholder || '').slice(0, 100);
        if (placeholder) input.setPlaceholder(placeholder);
        const minLength = Math.max(0, Math.min(4000, Number(field?.config?.min_length || 0)));
        if (minLength) input.setMinLength(minLength);
        modal.addComponents(new ActionRowBuilder().addComponents(input));
      });

      await interaction.showModal(modal);
      return;
    }

    if (interaction.isButton() && interaction.customId.startsWith('dh_claim:')) {
      const channel = interaction.channel;
      if (!channel?.isTextBased()) { await interaction.reply({ content: 'Ticket channel not found.', ephemeral: true }); return; }
      const meta = await getTicketMeta(channel);
      if (!meta) { await interaction.reply({ content: 'Ticket details could not be loaded. Please contact an administrator.', ephemeral: true }); return; }
      const roleIds = supportRoleIds(null, meta);
      const hasSupportRole = roleIds.some(id => interaction.member?.roles?.cache?.has(id));
      const canClaim = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) || hasSupportRole;
      if (!canClaim) { await interaction.reply({ content: 'Only assigned support team members can claim tickets.', ephemeral: true }); return; }
      const existing = String(meta.claimed_by || '');
      const canManageClaim = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels);
      const isUnclaim = existing === interaction.user.id || (Boolean(existing) && canManageClaim);
      if (existing && !isUnclaim) {
        await interaction.reply({ content: `This ticket is already claimed by <@${existing}>.`, ephemeral: true }); return;
      }
      try {
        const priorClaimMessageId = String(meta.claim_message_id || '');
        if (isUnclaim) {
          meta.claimed_by = ''; meta.claimed_name = ''; meta.claim_message_id = '';
        } else {
          const claimMessage = await channel.send({
            content: `🛠️ This ticket has been claimed by **${String(interaction.member?.displayName || interaction.user.globalName || interaction.user.username).replace(/[@<>]/g, '').slice(0, 80)}**.`,
            allowedMentions: { parse: [] }
          });
          meta.claimed_by = interaction.user.id; meta.claimed_name = interaction.user.username; meta.claim_message_id = claimMessage.id;
        }
        const rows = interaction.message.components.map(row => {
          const nextRow = ActionRowBuilder.from(row);
          nextRow.setComponents(nextRow.components.map(component => {
            const button = ButtonBuilder.from(component);
            if (button.data.custom_id?.startsWith('dh_claim:')) {
              button.setLabel(isUnclaim ? 'Claim Ticket' : 'Unclaim Ticket');
              button.setEmoji(isUnclaim ? '🙋' : '✋');
              button.setStyle(isUnclaim ? ButtonStyle.Primary : ButtonStyle.Success);
            }
            return button;
          }));
          return nextRow;
        });
        const embed = EmbedBuilder.from(interaction.message.embeds[0]).setFooter({ text: encodeTicketMeta(meta) });
        await interaction.update({ embeds: [embed], components: rows });
        ticketMetaCache.set(String(channel.id), meta);
        if (isUnclaim && priorClaimMessageId) {
          const claimMessage = await channel.messages.fetch(priorClaimMessageId).catch(() => null);
          if (claimMessage) await claimMessage.delete().catch(async error => {
            console.warn('Claim status message could not be removed:', error.message);
            await claimMessage.edit({ content: 'Ticket claim cleared.', allowedMentions: { parse: [] } }).catch(() => {});
          });
        }
        recordEvent(isUnclaim ? 'ticket_unclaimed' : 'ticket_claimed', interaction.guildId, interaction.user.id, interaction.user.username, 'ticket', channel.id);
      } catch (error) {
        console.error('Ticket claim toggle failed:', error.message);
        if (!interaction.replied && !interaction.deferred) await interaction.reply({ content: 'Could not update the claim status. Check bot permissions.', ephemeral: true }).catch(() => {});
      }
      return;
    }

    if (interaction.isButton() && interaction.customId.startsWith('dh_close:')) {
      const channel = interaction.channel;
      if (!channel || !channel.isTextBased() || !interaction.guild) {
        await interaction.reply({ content: 'Ticket channel not found.', ephemeral: true }); return;
      }
      const meta = await getTicketMeta(channel);
      if (!meta) { await interaction.reply({ content: 'Ticket metadata could not be loaded. The channel was not deleted.', ephemeral: true }); return; }
      const ownerId = String(meta.owner_discord_id || ''), ticketUser = String(meta.user_id || '');
      const roleIds = supportRoleIds(null, meta);
      const isSupport = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) || roleIds.some(id => interaction.member?.roles?.cache?.has(id));
      const canClose = isSupport || interaction.user.id === ticketUser;
      if (!canClose) { await interaction.reply({ content: 'Only the ticket owner or assigned support team can close this ticket.', ephemeral: true }); return; }
      if (!/^\d{15,22}$/.test(ownerId)) { await interaction.reply({ content: 'Workspace owner could not be verified. The channel was not deleted.', ephemeral: true }); return; }
      await interaction.deferReply({ ephemeral: true });
      try {
        const collected = []; let before;
        for (let page = 0; page < 10; page++) {
          const batch = await channel.messages.fetch({ limit: 100, ...(before ? { before } : {}) });
          if (!batch.size) break;
          collected.push(...batch.values()); before = batch.last().id;
          if (batch.size < 100 || collected.length >= 1000) break;
        }
        const messages = collected.slice(0, 1000).sort((a,b) => a.createdTimestamp - b.createdTimestamp).map(m => ({
          id: m.id, author_id: m.author.id, author_name: m.member?.displayName || m.author.globalName || m.author.username,
          author_avatar_url: m.author.displayAvatarURL({ size: 128 }), content: (m.content || '').slice(0, 2000),
          type: String(m.type), is_bot: m.author.bot,
          created_at: m.createdAt.toISOString().slice(0,19).replace('T',' '),
          edited_at: m.editedAt ? m.editedAt.toISOString().slice(0,19).replace('T',' ') : null,
          attachments: [...m.attachments.values()].slice(0,5).map(a => ({ id:a.id, name:a.name, content_type:a.contentType, size:a.size, url:a.url }))
        }));
        const closedBy = interaction.user.username;
        const firstBotEmbed = collected.find(m => m.author.id === client.user.id && m.embeds.length)?.embeds[0];
        const snapshot = {
          action: 'ticket_snapshot', owner_discord_id: ownerId, guild_id: interaction.guildId,
          discord_channel_id: channel.id, discord_user_id: ticketUser, user_name: String(meta.user_name || ''),
          title: String(meta.panel_title || firstBotEmbed?.title || channel.name), status: 'closed',
          claimed_by: String(meta.claimed_by || ''), claimed_by_name: String(meta.claimed_name || ''),
          close_by: interaction.user.id, close_by_name: closedBy, close_reason: 'Closed by ticket owner/support team',
          panel_id: Number(meta.panel_id || 0), panel_title: String(meta.panel_title || ''),
          ticket_number: Number(meta.ticket_number || 0), messages
        };
        let databaseSaved = false, transcriptSent = false, dmBackupSent = false, ticketCode = '';
        try {
          const result = await saveToWebsite(snapshot);
          databaseSaved = true; ticketCode = String(result.ticket_code || '');
        } catch (error) { console.error('Ticket transcript database save failed; trying Discord transcript backup:', error.message); }
        const transcriptText = `DIBIAA HUB TICKET TRANSCRIPT\nTicket: #${channel.name}\nPanel: ${meta.panel_title || meta.panel_id}\nTicket ID: ${meta.ticket_number || '—'}\nGuild: ${interaction.guild.name}\nClosed By: ${closedBy}\n\n` +
          messages.map(m => `[${m.created_at}] ${m.author_name} (${m.author_id})\n${m.content}${m.attachments.length ? '\nAttachments: ' + m.attachments.map(a => a.url).join(', ') : ''}`).join('\n\n');
        const makeTranscriptFile = () => new AttachmentBuilder(Buffer.from(transcriptText, 'utf8'), { name: `${channel.name}-transcript.txt` });
        const transcriptChannelId = String(meta.transcript_channel_id || '');
        if (/^\d{15,22}$/.test(transcriptChannelId)) {
          const transcriptChannel = await interaction.guild.channels.fetch(transcriptChannelId).catch(() => null);
          if (transcriptChannel?.isTextBased()) {
            try {
              await transcriptChannel.send({ content: `Transcript for **#${channel.name}** · Closed by ${closedBy}${ticketCode ? ` · ${ticketCode}` : ''}`, files: [makeTranscriptFile()] });
              transcriptSent = true;
            } catch (error) { console.error('Transcript channel delivery failed:', error.message); }
          }
        }
        if (!databaseSaved && !transcriptSent && /^\d{15,22}$/.test(ticketUser)) {
          try {
            const opener = await interaction.guild.members.fetch(ticketUser);
            await opener.send({ content: `Your ticket **#${channel.name}** has been closed. Here is its transcript for your records.`, files: [makeTranscriptFile()] });
            dmBackupSent = true;
          } catch (error) { console.error('Ticket transcript DM backup failed:', error.message); }
        }
        if (!databaseSaved && !transcriptSent && !dmBackupSent) {
          await interaction.editReply('Ticket transcript could not be backed up to the website, transcript channel, or ticket owner DM. The channel has been kept to prevent data loss. Configure a transcript channel and check the website API/database.');
          return;
        }
        recordEvent('ticket_closed', interaction.guildId, interaction.user.id, closedBy, 'ticket', channel.id, { owner_discord_id: ownerId, panel_id: meta.panel_id });
        const backupText = databaseSaved ? 'transcript saved to Dibiaa Hub' : transcriptSent ? 'transcript sent to the configured transcript channel' : 'transcript sent to the ticket owner';
        try {
          await channel.delete('Ticket closed; transcript backup completed');
          ticketMetaCache.delete(String(channel.id));
          await interaction.editReply(`Ticket closed successfully. ${ticketCode ? `Reference: ${ticketCode}. ` : ''}Channel deleted and ${backupText}.`);
        } catch (deleteError) {
          console.error('Ticket channel delete failed after transcript backup:', deleteError.message);
          let renamed = false, locked = false;
          try {
            const closedName = `closed-${channel.name}`.slice(0, 100);
            if (channel.name !== closedName) await channel.setName(closedName, 'Ticket closed; transcript backup completed');
            renamed = true;
          } catch (renameError) { console.error('Could not rename closed ticket channel:', renameError.message); }
          try {
            if (/^\d{15,22}$/.test(ticketUser)) await channel.permissionOverwrites.edit(ticketUser, { SendMessages: false });
            locked = true;
          } catch (permissionError) { console.error('Could not lock closed ticket channel:', permissionError.message); }
          if (locked) {
            ticketMetaCache.delete(String(channel.id));
            await channel.send('This ticket is closed. Its transcript has been backed up; contact support if you need to reopen it.').catch(() => {});
            await interaction.editReply(`Ticket closed and archived. ${ticketCode ? `Reference: ${ticketCode}. ` : ''}${backupText}. The bot could not delete the channel, so it was ${renamed ? 'renamed and ' : ''}locked instead.`);
          } else {
            await interaction.editReply(`The transcript is safely backed up (${backupText}), but the bot could not delete or lock this channel. Grant it Manage Channels and Manage Permissions so it can finish closing the ticket.`);
          }
        }
      } catch (error) {
        console.error('Ticket close operation failed:', error.message);
        await interaction.editReply('Ticket close failed before a safe transcript backup was confirmed. The channel has been kept so the conversation is not lost. Check bot Manage Channels permission and the transcript destination.');
      }
      return;
    }

    if (interaction.isModalSubmit() && interaction.customId.startsWith('dh_submit:')) {
      const panelId = interaction.customId.slice('dh_submit:'.length);
      const panel = panelCache.get(panelId);

      if (!panel) {
        await interaction.reply({
          content: 'This panel is no longer loaded. Please ask an admin to publish it again.',
          ephemeral: true
        });
        return;
      }

      const description = panel.questions.map((question, index) => {
        const answer = interaction.fields.getTextInputValue('q' + index);
        return `**${question}**\n${answer}`;
      }).join('\n\n');

      await interaction.deferReply({ ephemeral: true });

      let ticketChannel;
      try {
        ticketChannel = await createPrivateTicketChannel(interaction, panel, description);
      } catch (error) {
        console.error('Ticket channel creation failed:', error.message);
        await interaction.editReply(
          'Ticket channel create nahi ho paya. Bot ko Manage Channels permission aur category/role settings check karvao.'
        );
        return;
      }

      // Best-effort website DB sync. InfinityFree's free-hosting security challenge
      // blocks server-to-server API calls, so Discord ticket creation must not fail
      // just because the website API is unreachable.
      let databaseSaved = false;
      try {
        await saveToWebsite({
          action: 'ticket_create',
          title: String(panel.title || 'Support Ticket'),
          panel_id: Number(panel.id), panel_title: String(panel.title || ''),
          ticket_number: Number(ticketMetaCache.get(String(ticketChannel.id))?.ticket_number || 0),
          description,
          discord_user_id: interaction.user.id,
          user_name: interaction.user.username,
          discord_channel_id: ticketChannel.id,
          guild_id: interaction.guildId,
          owner_discord_id: panel.owner_discord_id
        });
        databaseSaved = true;
      } catch (error) {
        console.error('Ticket created in Discord, but website DB sync failed:', error.message);
      }

      const syncMessage = databaseSaved
        ? 'Ticket channel create ho gaya aur website database mein save bhi ho gaya.'
        : 'Ticket channel create ho gaya. Note: InfinityFree security protection ki wajah se website database sync nahi hua; ticket channel Discord mein available hai.';

      await interaction.editReply(`${syncMessage}\nChannel: <#${ticketChannel.id}>`);
      return;
    }
  } catch (error) {
    console.error('Interaction error:', error.message);
    if (interaction.isRepliable() && !interaction.replied && !interaction.deferred) {
      await interaction.reply({
        content: 'Something went wrong. Please try again or contact an admin.',
        ephemeral: true
      }).catch(() => {});
    }
  }
});

client.on('guildMemberRemove', async member => {
  try {
    const channels = await member.guild.channels.fetch();
    for (const channel of channels.values()) {
      if (!channel || !channel.isTextBased() || !maybeTicketChannel(channel)) continue;
      const meta = await getTicketMeta(channel);
      const userId = String(meta?.user_id || ''), panelId = String(meta?.panel_id || '');
      if (userId !== member.id || !panelId) continue;
      const panel = panelCache.get(panelId);
      if (!(meta.close_on_user_leave || panel?.settings?.close_on_user_leave)) continue;
      await channel.setName(('closed-' + channel.name).slice(0, 100), 'Ticket creator left the server; auto-closed by panel settings').catch(() => {});
      await channel.permissionOverwrites.edit(member.id, { SendMessages: false }).catch(() => {});
      await channel.send('Ticket auto-closed because the ticket creator left this server.');
    }
  } catch (error) {
    console.error('Auto-close on member leave failed:', error.message);
  }
});

client.once('clientReady', () => {
  console.log(`Dibiaa Hub bot online as ${client.user.tag}`);
});

const port = Number(process.env.PORT || 3000);
app.listen(port, '0.0.0.0', () => {
  console.log('Bot API listening on port ' + port);
});

if (!token) {
  console.error('DISCORD_TOKEN is missing');
} else {
  client.login(token).catch(error => {
    console.error('Discord bot login failed:', error.message);
  });
}
