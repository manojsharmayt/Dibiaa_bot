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
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

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
// Validate HTTPS URLs using the URL parser. The previous regex accidentally
// required THREE slashes after https:, rejecting valid https:// addresses.
function isValidHttpsUrl(value) {
  try {
    const parsed = new URL(String(value || '').trim());
    return parsed.protocol === 'https:' && Boolean(parsed.hostname) &&
      !parsed.username && !parsed.password;
  } catch {
    return false;
  }
}
if (!isValidHttpsUrl(publicBaseUrl) || !isValidHttpsUrl(discordRedirectUri)) {
  console.error('PUBLIC_BASE_URL and DISCORD_REDIRECT_URI must be valid HTTPS URLs (https://host/path).');
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

// Keep ticket metadata machine-readable without exposing IDs in Discord's channel welcome text.
const TOPIC_B64 = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const TOPIC_INVISIBLE_BASE = 0xE0100;
function encodeTicketTopic(meta) {
  const packed = Buffer.from(JSON.stringify(meta), 'utf8').toString('base64url');
  const hidden = [...packed].map(ch => String.fromCodePoint(TOPIC_INVISIBLE_BASE + TOPIC_B64.indexOf(ch))).join('');
  const displayName = String(meta.user_name || 'member').replace(/[\r\n|]/g, ' ').slice(0, 45);
  return (`Private support ticket • Opened by ${displayName}\u2063${hidden}`).slice(0, 1024);
}
function decodeTicketTopic(topic = '') {
  const value = String(topic || '');
  const marker = value.lastIndexOf('\u2063');
  if (marker >= 0) {
    try {
      const packed = [...value.slice(marker + 1)].map(ch => {
        const index = ch.codePointAt(0) - TOPIC_INVISIBLE_BASE;
        return index >= 0 && index < TOPIC_B64.length ? TOPIC_B64[index] : '';
      }).join('');
      if (packed) return JSON.parse(Buffer.from(packed, 'base64url').toString('utf8'));
    } catch {}
  }
  // Backward compatibility for tickets created with the older visible topic format.
  const get = (label) => value.match(new RegExp(label + ':\\s*([^|]+)'))?.[1]?.trim() || '';
  return {
    owner_discord_id: get('Owner ID'), user_id: get('User ID'), user_name: get('User Name'),
    panel_id: get('Panel'), support_role_id: get('Support Role ID'), transcript_channel_id: get('Transcript Channel ID'),
    claimed_by: get('Claimed By'), claimed_by_name: get('Claimed Name')
  };
}
function setTicketMeta(channel, meta) {
  return channel.setTopic(encodeTicketTopic(meta));
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
    signal: AbortSignal.timeout(8000)
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
  const hidden = decodeHiddenTag(footer);
  const legacyMatch = footer.match(/DH1:([A-Za-z0-9_-]+)/);
  const packed = hidden || legacyMatch?.[1];
  if (!packed) throw new Error('Panel form data is unavailable. Ask an admin to republish the panel.');
  panel = JSON.parse(inflateRawSync(Buffer.from(packed, 'base64url')).toString('utf8'));
  if (String(panel.id) !== String(data.panel_id)) throw new Error('Panel token does not match.');
  panelCache.set(String(panel.id), panel);
  return panel;
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
    if (panel.settings?.enabled === 0) return res.status(403).send('This ticket panel is disabled.');
    const fields = Array.isArray(panel.form_fields) ? panel.form_fields : [];
    if (!fields.length) return res.status(400).send('No form fields are configured. Please ask an admin to edit the panel.');
    const uploadWarning = fields.some(f => ['file','image'].includes(f.type)) ? '<div class="upload-warning">File upload storage is not configured for this deployment. Upload fields are disabled; please describe the file instead.</div>' : '';
    const controls = fields.map((f,i)=>`<label class="field"><span>${htmlEscape(f.label||`Question ${i+1}`)}${f.required&&f.type!=='static'?' *':''}</span>${f.help_text?`<small>${htmlEscape(f.help_text)}</small>`:''}${webControl(f)}</label>`).join('');
    res.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'");
    res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(panel.title)} · Dibiaa</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Lora:wght@400;500;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box}body{margin:0;background:#f6f7fb;color:#172033;font:15px/1.6 Lora,Georgia,serif}.wrap{max-width:760px;margin:35px auto;padding:20px}.card{background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:28px;box-shadow:0 12px 35px #17203310}h1{margin:0 0 8px;font-size:28px}p{color:#64748b}.field{display:grid;gap:8px;margin:20px 0}.field>span{font-weight:600}.field small{color:#64748b}input,textarea,select{font:inherit;width:100%;padding:11px 12px;border:1px solid #cbd5e1;border-radius:9px;background:white;color:#172033}.options{display:grid;gap:9px}.options label,.check{display:flex;gap:9px;align-items:center}.options input,.check input{width:auto}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.static{padding:12px;background:#f8fafc;border-radius:8px}.upload-warning{background:#fff7ed;color:#9a3412;padding:12px;border-radius:8px}.btn{background:#e11d48;color:#fff;border:0;border-radius:10px;padding:12px 18px;font:inherit;cursor:pointer;width:100%;margin-top:8px}@media(max-width:600px){.wrap{margin:10px auto;padding:10px}.card{padding:18px}.two{grid-template-columns:1fr}}</style></head><body><main class="wrap"><section class="card"><p>DIBIAA HUB · SUPPORT</p><h1>${htmlEscape(panel.title)}</h1><p>${htmlEscape(panel.description||'Please complete this form to open a ticket.')}</p><form method="post" action="/ticket-form/${htmlEscape(req.params.token)}">${uploadWarning}${controls}<button class="btn" type="submit">Submit and Open Ticket</button></form></section></main></body></html>`);
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
    const username = String(member.user.username||'user').toLowerCase().replace(/[^a-z0-9-]/g,'-').replace(/-+/g,'-').replace(/^-|-$/g,'').slice(0,18)||'user';
    const scheme = String(panel.settings?.naming_scheme||'ticket-{username}');
    const channelName = scheme.replaceAll('{username}',username).replaceAll('{id}',String(Date.now()).slice(-6)).replace(/[^a-z0-9-]/gi,'-').replace(/-+/g,'-').slice(0,90)||`ticket-${username}`;
    const overwrites = [
      {id:guild.id,deny:[PermissionFlagsBits.ViewChannel]},
      {id:member.id,allow:[PermissionFlagsBits.ViewChannel,PermissionFlagsBits.SendMessages,PermissionFlagsBits.ReadMessageHistory,...(panel.settings?.permission_attachments===0?[]:[PermissionFlagsBits.AttachFiles]),...(panel.settings?.permission_embeds===0?[]:[PermissionFlagsBits.EmbedLinks])]},
      {id:client.user.id,allow:[PermissionFlagsBits.ViewChannel,PermissionFlagsBits.SendMessages,PermissionFlagsBits.ReadMessageHistory,PermissionFlagsBits.ManageChannels,PermissionFlagsBits.EmbedLinks]}
    ];
    const roleId=String(panel.settings?.support_role_id||'');
    if(roleId&&/^\d+$/.test(roleId))overwrites.push({id:roleId,allow:[PermissionFlagsBits.ViewChannel,PermissionFlagsBits.SendMessages,PermissionFlagsBits.ReadMessageHistory,PermissionFlagsBits.AttachFiles]});
    const createOptions={name:channelName,type:ChannelType.GuildText,topic:encodeTicketTopic({owner_discord_id:String(panel.owner_discord_id),user_id:String(member.id),user_name:String(member.user.username),panel_id:String(panel.id),support_role_id:String(panel.settings?.support_role_id||''),transcript_channel_id:String(panel.settings?.transcript_channel_id||''),claimed_by:'',claimed_by_name:''}),permissionOverwrites:overwrites};
    const category=String(panel.settings?.ticket_category_id||'');if(category&&/^\d+$/.test(category))createOptions.parent=category;
    const ticketChannel=await guild.channels.create(createOptions);
    recordEvent('ticket_created', guild.id, member.id, member.user.username, 'ticket', ticketChannel.id, {owner_discord_id:panel.owner_discord_id});
    const answerText=answers.join('\n\n')||'No answers provided.';
    const embed=new EmbedBuilder().setTitle(String(panel.title||'Support Ticket').slice(0,256)).setDescription(answerText.slice(0,4000)).setColor(/^#[0-9a-fA-F]{6}$/.test(String(panel.settings?.panel_colour||''))?Number.parseInt(String(panel.settings.panel_colour).slice(1),16):0x433d8b).addFields({name:'Opened by',value:`<@${member.id}>`,inline:true}).setTimestamp();
    const buttons=[];
    if(!(panel.settings?.hide_close_button||panel.settings?.allow_user_close===0)){
      buttons.push(new ButtonBuilder().setCustomId('dh_close:'+ticketChannel.id).setLabel('Close').setEmoji('🔒').setStyle(ButtonStyle.Danger));
      buttons.push(new ButtonBuilder().setCustomId('dh_close_reason:'+ticketChannel.id).setLabel('Close With Reason').setEmoji('📝').setStyle(ButtonStyle.Secondary));
    }
    if(!panel.settings?.hide_claim_button)buttons.push(new ButtonBuilder().setCustomId(`dh_claim:${ticketChannel.id}:${panel.id}`).setLabel('Claim').setEmoji('🙋').setStyle(ButtonStyle.Primary));
    const supportMention=panel.settings?.mention_support&&roleId?`<@&${roleId}> `:'';
    await ticketChannel.send({content:`${supportMention}<@${member.id}>`,embeds:[embed],components:buttons.length?[new ActionRowBuilder().addComponents(buttons)]:[],allowedMentions:{users:[member.id],roles:supportMention?[roleId]:[]}});
    usedFormTokens.add(req.params.token);
    try { await saveToWebsite({action:'ticket_create',title:String(panel.title||'Support Ticket'),description:answerText,discord_user_id:member.id,user_name:member.user.username,discord_channel_id:ticketChannel.id,guild_id:guild.id,owner_discord_id:panel.owner_discord_id}); } catch (error) { console.error('Web form ticket DB sync failed:',error.message); }
    return res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ticket opened</title><style>body{font:18px/1.6 Lora,Georgia,serif;background:#f6f7fb;color:#172033;padding:24px}.card{max-width:600px;margin:8vh auto;background:#fff;padding:28px;border-radius:16px}a{color:#e11d48}</style></head><body><main class="card"><h1>Ticket opened successfully</h1><p>Your ticket channel is <a href="https://discord.com/channels/${guild.id}/${ticketChannel.id}">#${htmlEscape(ticketChannel.name)}</a>.</p><p>You can return to Discord now.</p></main></body></html>`);
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
      if (!channel || !channel.isTextBased() || !channel.topic) continue;
      const ticketMeta = decodeTicketTopic(channel.topic);
      if (String(ticketMeta.owner_discord_id || '') !== ownerId) continue;
      if (!/^\d{15,22}$/.test(String(ticketMeta.user_id || ''))) continue;
      let messageDescription = '';
      let embedTitle = channel.name || 'Discord Ticket';
      try {
        const messages = await channel.messages.fetch({ limit: 25 });
        const botMessage = messages.find(m => m.author.id === client.user.id && m.embeds.length);
        if (botMessage && botMessage.embeds[0]) {
          const embed = botMessage.embeds[0];
          embedTitle = embed.title || embedTitle;
          messageDescription = embed.description || '';
        }
      } catch (err) {
        console.error('Ticket channel read failed:', channel.id, err.message);
      }
      let userName = String(ticketMeta.user_name || '');
      if (!userName) { try { userName = (await guild.members.fetch(String(ticketMeta.user_id))).user.username; } catch {} }
      tickets.push({
        title: embedTitle, user_name: userName, owner_discord_id: ownerId,
        description: messageDescription || 'Ticket created in Discord.',
        discord_user_id: String(ticketMeta.user_id),
        discord_channel_id: channel.id,
        guild_id: guildId,
        status: channel.name.startsWith('closed-') ? 'closed' : 'open',
        claimed_by: String(ticketMeta.claimed_by || ''),
        claimed_by_name: String(ticketMeta.claimed_by_name || ''),
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
    const ticketMeta = decodeTicketTopic(channel?.topic || '');
    if (!channel || !channel.isTextBased() || String(ticketMeta.owner_discord_id || '') !== ownerId) return res.status(404).json({ ok:false, error:'Ticket not found for this owner/server' });
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
      settings: safeSettings
    };
    const colourText = /^#[0-9a-fA-F]{6}$/.test(String(safeSettings.panel_colour || '')) ? String(safeSettings.panel_colour) : '#433d8b';
    const packed = deflateRawSync(Buffer.from(JSON.stringify(safePanel))).toString('base64url');
    const footerText = 'Dibiaa Hub • Ticket Panel • ' + encodeHiddenTag(packed);
    if (footerText.length > 2048) return res.status(413).json({ ok: false, error: 'This form configuration is too large to embed safely in a Discord panel. Reduce the number/size of fields.' });
    const embed = new EmbedBuilder()
      .setTitle(safePanel.title)
      .setDescription(safePanel.description)
      .setColor(colourText)
      .setFooter({ text: footerText });
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
    const hidden = decodeHiddenTag(oldFooter);
    const legacyMatch = oldFooter.match(/DH1:([A-Za-z0-9_-]+)/);
    const packedFooter = hidden || legacyMatch?.[1];
    let panel = panelCache.get(String(panel_id));
    if (packedFooter) {
      try { panel = JSON.parse(inflateRawSync(Buffer.from(packedFooter, 'base64url')).toString('utf8')); } catch {}
    }
    if (!panel || String(panel.owner_discord_id || '') !== String(owner_discord_id) || String(panel.guild_id || '') !== String(guild_id)) return res.status(404).json({ ok: false, error: 'Panel configuration could not be recovered for this owner/server.' });
    panel.settings = { ...(panel.settings || {}), enabled: enabled ? 1 : 0 };
    panelCache.set(String(panel_id), panel);
    const packed = deflateRawSync(Buffer.from(JSON.stringify(panel))).toString('base64url');
    const embed = oldEmbed ? EmbedBuilder.from(oldEmbed).setFooter({ text: ('Dibiaa Hub • Ticket Panel • ' + encodeHiddenTag(packed)).slice(0, 2048) }) : null;
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

async function createPrivateTicketChannel(interaction, panel, description) {
  const guild = interaction.guild;
  if (!guild) throw new Error('Tickets can only be opened inside a server.');

  const member = interaction.member;
  const username = (interaction.user.username || 'user')
    .toLowerCase()
    .replace(/[^a-z0-9-]/g, '-')
    .replace(/-+/g, '-')
    .replace(/^-|-$/g, '')
    .slice(0, 18) || 'user';

  const scheme = String(panel.settings?.naming_scheme || 'ticket-{username}');
  const baseName = scheme.replaceAll('{username}', username).replaceAll('{id}', String(Date.now()).slice(-6)).replace(/[^a-z0-9-]/gi, '-').replace(/-+/g, '-').slice(0, 90) || `ticket-${username}`;
  const overwrites = [
    {
      id: guild.id,
      deny: [PermissionFlagsBits.ViewChannel]
    },
    {
      id: interaction.user.id,
      allow: [
        PermissionFlagsBits.ViewChannel,
        PermissionFlagsBits.SendMessages,
        PermissionFlagsBits.ReadMessageHistory,
        ...(panel.settings?.permission_attachments === 0 ? [] : [PermissionFlagsBits.AttachFiles]),
        ...(panel.settings?.permission_embeds === 0 ? [] : [PermissionFlagsBits.EmbedLinks])
      ]
    }
  ];

  if (client.user) {
    overwrites.push({
      id: client.user.id,
      allow: [
        PermissionFlagsBits.ViewChannel,
        PermissionFlagsBits.SendMessages,
        PermissionFlagsBits.ReadMessageHistory,
        PermissionFlagsBits.ManageChannels,
        PermissionFlagsBits.EmbedLinks
      ]
    });
  }

  const panelSupportRole = String(panel.settings?.support_role_id || supportRoleId || '');
  if (panelSupportRole && /^\d+$/.test(panelSupportRole)) {
    overwrites.push({
      id: panelSupportRole,
      allow: [
        PermissionFlagsBits.ViewChannel,
        PermissionFlagsBits.SendMessages,
        PermissionFlagsBits.ReadMessageHistory,
        PermissionFlagsBits.AttachFiles
      ]
    });
  }

  const options = {
    name: baseName,
    type: ChannelType.GuildText,
    topic: encodeTicketTopic({owner_discord_id:String(panel.owner_discord_id),user_id:String(interaction.user.id),user_name:String(interaction.user.username),panel_id:String(panel.id),support_role_id:String(panel.settings?.support_role_id||''),transcript_channel_id:String(panel.settings?.transcript_channel_id||''),claimed_by:'',claimed_by_name:''}),
    permissionOverwrites: overwrites
  };

  const panelCategoryId = String(panel.settings?.ticket_category_id || ticketCategoryId || '');
  if (panelCategoryId && /^\d+$/.test(panelCategoryId)) options.parent = panelCategoryId;

  const channel = await guild.channels.create(options);
  recordEvent('ticket_created', guild.id, interaction.user.id, interaction.user.username, 'ticket', channel.id, {owner_discord_id:panel.owner_discord_id});
  const embed = new EmbedBuilder()
    .setTitle(String(panel.title || 'Support Ticket').slice(0, 256))
    .setDescription(description.slice(0, 4000))
    .setColor(0x433d8b)
    .addFields({ name: 'Opened by', value: `<@${interaction.user.id}>`, inline: true })
    .setTimestamp();

  const ticketButtons = [];
  if (!(panel.settings?.hide_close_button || panel.settings?.allow_user_close === 0)) {
    ticketButtons.push(new ButtonBuilder().setCustomId('dh_close:' + channel.id).setLabel('Close').setEmoji('🔒').setStyle(ButtonStyle.Danger));
    ticketButtons.push(new ButtonBuilder().setCustomId('dh_close_reason:' + channel.id).setLabel('Close With Reason').setEmoji('📝').setStyle(ButtonStyle.Secondary));
  }
  if (!panel.settings?.hide_claim_button) {
    ticketButtons.push(new ButtonBuilder().setCustomId('dh_claim:' + channel.id + ':' + panel.id).setLabel('Claim').setEmoji('🙋').setStyle(ButtonStyle.Primary));
  }
  const ticketComponents = ticketButtons.length ? [new ActionRowBuilder().addComponents(ticketButtons)] : [];

  await channel.send({
    content: (panel.settings?.mention_support && panel.settings?.support_role_id) ? `<@&${panel.settings.support_role_id}> <@${interaction.user.id}>` : (supportRoleId && !panel.settings ? `<@&${supportRoleId}> <@${interaction.user.id}>` : `<@${interaction.user.id}>`),
    embeds: [embed],
    components: ticketComponents,
    allowedMentions: {
      users: [interaction.user.id],
      roles: (panel.settings?.mention_support && panel.settings?.support_role_id) ? [panel.settings.support_role_id] : (supportRoleId && !panel.settings ? [supportRoleId] : [])
    }
  });

  return channel;
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


async function archiveTicket(interaction, closeReason) {
  const channel = interaction.channel;
  if (!channel || !channel.isTextBased() || !interaction.guild) {
    if (interaction.isButton()) await interaction.reply({ content: 'Ticket channel not found.', ephemeral: true });
    else await interaction.reply({ content: 'Ticket channel not found.', ephemeral: true });
    return;
  }
  const meta = decodeTicketTopic(channel.topic || '');
  const ownerId = String(meta.owner_discord_id || '');
  const ticketUser = String(meta.user_id || '');
  const panelId = String(meta.panel_id || '');
  const panel = panelCache.get(panelId) || {};
  const roleId = String(panel.settings?.support_role_id || meta.support_role_id || '');
  const isSupport = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) ||
    Boolean(roleId && interaction.member?.roles?.cache?.has(roleId));
  if (!(isSupport || interaction.user.id === ticketUser)) {
    if (interaction.isButton()) await interaction.reply({ content: 'Only the ticket owner or a support moderator can close this ticket.', ephemeral: true });
    else await interaction.reply({ content: 'Only the ticket owner or a support moderator can close this ticket.', ephemeral: true });
    return;
  }
  if (!/^\d{15,22}$/.test(ownerId)) {
    const msg = 'This ticket is missing its workspace owner reference. The channel was kept safe.';
    if (interaction.deferred) await interaction.editReply(msg); else await interaction.reply({content:msg,ephemeral:true});
    return;
  }
  if (!interaction.deferred) await interaction.deferReply({ ephemeral: true });
  try {
    const collected = []; let before;
    for (let page=0; page<10; page++) {
      const batch = await channel.messages.fetch({ limit:100, ...(before ? {before} : {}) });
      if (!batch.size) break;
      collected.push(...batch.values()); before=batch.last().id;
      if (batch.size<100 || collected.length>=1000) break;
    }
    const messages = collected.slice(0,1000).sort((a,b)=>a.createdTimestamp-b.createdTimestamp).map(m=>({
      id:m.id,author_id:m.author.id,author_name:m.member?.displayName||m.author.globalName||m.author.username,
      author_avatar_url:m.author.displayAvatarURL({size:128}),content:m.content||'',type:String(m.type),is_bot:m.author.bot,
      created_at:m.createdAt.toISOString().slice(0,19).replace('T',' '),edited_at:m.editedAt?m.editedAt.toISOString().slice(0,19).replace('T',' '):null,
      attachments:[...m.attachments.values()].map(a=>({id:a.id,name:a.name,content_type:a.contentType,size:a.size,url:a.url}))
    }));
    const closedBy = interaction.user.username;
    const snapshot = await saveToWebsite({action:'ticket_snapshot',owner_discord_id:ownerId,guild_id:interaction.guildId,discord_channel_id:channel.id,discord_user_id:ticketUser,user_name:String(meta.user_name||''),title:(collected.find(m=>m.author.id===client.user.id&&m.embeds.length)?.embeds[0]?.title)||channel.name.replace(/^closed-/,'').replace(/-/g,' '),status:'closed',claimed_by:String(meta.claimed_by||''),claimed_by_name:String(meta.claimed_by_name||''),close_by:interaction.user.id,close_by_name:closedBy,close_reason:String(closeReason||'Closed'),messages});
    const transcriptChannelId=String(panel.settings?.transcript_channel_id||meta.transcript_channel_id||'');
    if (/^\d{15,22}$/.test(transcriptChannelId)) {
      const transcriptChannel=await interaction.guild.channels.fetch(transcriptChannelId).catch(()=>null);
      if (transcriptChannel?.isTextBased()) {
        const lines=messages.map(m=>`[${m.created_at}] ${m.author_name}\n${m.content}${m.attachments.length?'\nAttachments: '+m.attachments.map(a=>a.url).join(', '):''}`).join('\n\n');
        const file=new AttachmentBuilder(Buffer.from(`DIBIAA HUB TICKET TRANSCRIPT\nTicket Channel: ${channel.id}\nClosed By: ${closedBy}\nClose Reason: ${closeReason}\n\n${lines}`,'utf8'),{name:`ticket-${channel.id}-transcript.txt`});
        await transcriptChannel.send({content:`Transcript for closed ticket #${channel.name}`,files:[file]});
      }
    }
    recordEvent('ticket_closed',interaction.guildId,interaction.user.id,closedBy,'ticket',channel.id,{owner_discord_id:ownerId,close_reason:closeReason});
    await channel.delete('Ticket closed; transcript and ticket data saved to Dibiaa Hub');
    await interaction.editReply(`Ticket closed. ${snapshot.ticket_code ? `Reference: ${snapshot.ticket_code}. ` : ''}The ticket channel has been removed and its transcript was saved.`);
  } catch (error) {
    console.error('Ticket close/snapshot failed:',error.message);
    await interaction.editReply('Ticket could not be safely closed. The channel was kept so its conversation is not lost. Check the website API/database and bot permissions.');
  }
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
          const hidden = decodeHiddenTag(footer);
          const legacyMatch = footer.match(/DH1:([A-Za-z0-9_-]+)/);
          const packed = hidden || legacyMatch?.[1];
          if (packed) {
            const recovered = JSON.parse(inflateRawSync(Buffer.from(packed, 'base64url')).toString('utf8'));
            if (String(recovered.id) === panelId && Array.isArray(recovered.questions)) {
              panel = recovered;
              panelCache.set(panelId, panel);
            }
          }
        } catch (error) {
          console.error('Panel recovery failed:', error.message);
        }
      }

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
        const openCount = channels ? [...channels.values()].filter(ch =>
          ch && ch.isTextBased() && ch.topic &&
          String(decodeTicketTopic(ch.topic).user_id || '') === interaction.user.id &&
          String(decodeTicketTopic(ch.topic).panel_id || '') === panelId &&
          !String(ch.name || '').startsWith('closed-')
        ).length : 0;
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
      const parts = interaction.customId.split(':');
      const channel = interaction.channel;
      const panelId = parts[2] || '';
      const panel = panelCache.get(panelId);
      const topic = channel?.topic || '';
      const ticketMeta = decodeTicketTopic(topic);
      const supportRoleId = String(panel?.settings?.support_role_id || ticketMeta.support_role_id || '');
      const hasSupportRole = Boolean(supportRoleId && interaction.member?.roles?.cache?.has(supportRoleId));
      const canClaim = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) || hasSupportRole;
      if (!channel || !canClaim) {
        await interaction.reply({ content: 'Only support team members can claim tickets.', ephemeral: true });
        return;
      }
      const existing = String(ticketMeta.claimed_by || '');
      const isUnclaim = existing === interaction.user.id;
      if (existing && !isUnclaim) {
        await interaction.reply({ content: `This ticket is already claimed by <@${existing}>.`, ephemeral: true });
        return;
      }
      if (existing && !isUnclaim && !interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels)) return;
      try {
        ticketMeta.claimed_by = isUnclaim ? '' : interaction.user.id;
        ticketMeta.claimed_by_name = isUnclaim ? '' : interaction.user.username;
        await setTicketMeta(channel, ticketMeta);
        const rows = interaction.message.components.map(row => {
          const nextRow = ActionRowBuilder.from(row);
          nextRow.setComponents(nextRow.components.map(component => {
            const button = ButtonBuilder.from(component);
            if (button.data.custom_id?.startsWith('dh_claim:')) {
              button.setLabel(isUnclaim ? 'Claim' : 'Unclaim');
              button.setStyle(isUnclaim ? ButtonStyle.Primary : ButtonStyle.Success);
            }
            return button;
          }));
          return nextRow;
        });
        await interaction.update({ components: rows });
        recordEvent(isUnclaim ? 'ticket_unclaimed' : 'ticket_claimed', interaction.guildId, interaction.user.id, interaction.user.username, 'ticket', channel.id);
      } catch (error) {
        console.error('Ticket claim toggle failed:', error.message);
        if (!interaction.replied && !interaction.deferred) await interaction.reply({ content: 'Could not update the ticket claim state. Check Manage Channels permission.', ephemeral: true });
      }
      return;
    }

    if (interaction.isButton() && interaction.customId.startsWith('dh_close_reason:')) {
      const channel = interaction.channel;
      const meta = decodeTicketTopic(channel?.topic || '');
      const panel = panelCache.get(String(meta.panel_id || '')) || {};
      const roleId = String(panel.settings?.support_role_id || meta.support_role_id || '');
      const allowed = interaction.user.id === String(meta.user_id || '') ||
        interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) ||
        Boolean(roleId && interaction.member?.roles?.cache?.has(roleId));
      if (!channel || !allowed) { await interaction.reply({content:'Only the ticket owner or support team can close this ticket.',ephemeral:true}); return; }
      const modal = new ModalBuilder().setCustomId('dh_close_reason_submit:' + channel.id).setTitle('Close ticket with reason');
      const reasonInput = new TextInputBuilder().setCustomId('close_reason').setLabel('Reason for closing').setStyle(TextInputStyle.Paragraph).setRequired(true).setMaxLength(800).setPlaceholder('Write a short reason for closing this ticket...');
      modal.addComponents(new ActionRowBuilder().addComponents(reasonInput));
      await interaction.showModal(modal);
      return;
    }

    if (interaction.isModalSubmit() && interaction.customId.startsWith('dh_close_reason_submit:')) {
      const reason = interaction.fields.getTextInputValue('close_reason').trim();
      await archiveTicket(interaction, reason || 'Closed with reason');
      return;
    }

    if (interaction.isButton() && interaction.customId.startsWith('dh_close:')) {
      await archiveTicket(interaction, 'Closed without a reason');
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
      if (!channel || !channel.isTextBased() || !channel.topic) continue;
      const meta = decodeTicketTopic(channel.topic);
      const userId = String(meta.user_id || '');
      const panelId = String(meta.panel_id || '');
      if (userId !== member.id || !panelId || String(channel.name || '').startsWith('closed-')) continue;
      const panel = panelCache.get(panelId);
      if (!panel?.settings?.close_on_user_leave) continue;
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
