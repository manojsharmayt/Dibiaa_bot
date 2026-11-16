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
  PermissionFlagsBits,
  SnowflakeUtil
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
  const provided = Buffer.from(String(req.get('X-API-Key') || ''));
  const expected = Buffer.from(String(apiKey || ''));
  return Boolean(apiKey) && provided.length === expected.length && crypto.timingSafeEqual(provided, expected);
}

const BRAND_COLOUR = 0x6A89A7; // Stormy Morning palette (matches the website)
const BRAND_HEX = '#6A89A7';
const ticketTopicValue = (topic, label) => String(topic || '').match(new RegExp(label + ':\\s*([^|]*)'))?.[1]?.trim() || '';
const topicSafe = value => String(value ?? '').replace(/[|\r\n]+/g, ' ').trim();

/** Topic written on every ticket channel. Flags let the bot keep behaving correctly after a restart. */
function buildTicketTopic(panel, user) {
  const s = panel.settings || {};
  const parts = [
    'Dibiaa ticket', `Owner ID: ${panel.owner_discord_id}`, `User ID: ${user.id}`, `User Name: ${topicSafe(user.username).slice(0, 40)}`,
    `Panel: ${panel.id}`, `Support Role ID: ${s.support_role_id || ''}`, `Transcript Channel ID: ${s.transcript_channel_id || ''}`,
    `Opened At: ${new Date().toISOString()}`
  ];
  if (Number(s.auto_close) === 1) parts.push(`Auto Close Hours: ${Math.max(1, Math.min(8760, Number(s.auto_close_hours || 72)))}`);
  if (Number(s.user_feedback) === 1) parts.push('Feedback: 1');
  if (Number(s.close_confirmation) === 0) parts.push('Confirm Close: 0');
  return parts.join(' | ').slice(0, 1024);
}

/** One serialised Discord message, shared by the transcript endpoint and the close snapshot. */
function serializeMessage(m) {
  const mentions = { users: {}, roles: {}, channels: {} };
  try {
    m.mentions?.users?.forEach(u => { mentions.users[u.id] = m.mentions.members?.get(u.id)?.displayName || u.globalName || u.username; });
    m.mentions?.roles?.forEach(r => { mentions.roles[r.id] = r.name; });
    m.mentions?.channels?.forEach(c => { if (c?.name) mentions.channels[c.id] = c.name; });
  } catch {}
  const embeds = (m.embeds || []).slice(0, 5).map(e => ({
    title: e.title || null, description: e.description || null, url: e.url || null, color: e.color ?? null,
    author: e.author?.name ? { name: e.author.name } : null,
    fields: (e.fields || []).slice(0, 25).map(f => ({ name: f.name, value: f.value, inline: Boolean(f.inline) })),
    footer: e.footer?.text ? { text: e.footer.text.replace(/[\u{E0100}-\u{E01EF}]/gu, '').slice(0, 300) } : null,
    image: e.image?.url ? { url: e.image.url } : null,
    thumbnail: e.thumbnail?.url ? { url: e.thumbnail.url } : null
  }));
  const styleNames = { 1: 'primary', 2: 'secondary', 3: 'success', 4: 'danger', 5: 'link' };
  const components = [];
  for (const row of m.components || []) for (const c of row.components || []) {
    if (c.label) components.push({ label: String(c.label).slice(0, 80), style: styleNames[c.style] || 'secondary', emoji: c.emoji?.name && !c.emoji.id ? c.emoji.name : '' });
  }
  return {
    id: m.id, author_id: m.author.id, author_name: m.member?.displayName || m.author.globalName || m.author.username,
    author_avatar_url: m.author.displayAvatarURL({ size: 128 }), content: m.content || '', type: String(m.type), is_bot: m.author.bot,
    created_at: m.createdAt.toISOString().slice(0, 19).replace('T', ' '),
    edited_at: m.editedAt ? m.editedAt.toISOString().slice(0, 19).replace('T', ' ') : null,
    attachments: [...m.attachments.values()].map(a => ({ id: a.id, name: a.name, content_type: a.contentType, size: a.size, url: a.url })),
    embeds, components, mentions
  };
}

async function fetchAllMessages(channel, limit = 1000) {
  const collected = []; let before;
  for (let page = 0; page < Math.ceil(limit / 100); page++) {
    const batch = await channel.messages.fetch({ limit: 100, ...(before ? { before } : {}) });
    if (!batch.size) break;
    collected.push(...batch.values()); before = batch.last().id;
    if (batch.size < 100 || collected.length >= limit) break;
  }
  return collected.slice(0, limit).sort((a, b) => a.createdTimestamp - b.createdTimestamp);
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

app.get('/health', (req, res) => {
  res.json({ ok: true, botReady: client.isReady(), uptime_seconds: Math.round(process.uptime()) });
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
    res.type('html').send(`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>${htmlEscape(panel.title)} · Dibiaa</title><link rel="preconnect" href="https://fonts.googleapis.com"><link href="https://fonts.googleapis.com/css2?family=Lora:wght@400;500;600;700&display=swap" rel="stylesheet"><style>*{box-sizing:border-box}body{margin:0;background:#F3F8FE;color:#384959;font:15px/1.6 Lora,Georgia,serif}.wrap{max-width:760px;margin:35px auto;padding:20px}.card{background:#fff;border:1px solid #e5e7eb;border-radius:18px;padding:28px;box-shadow:0 12px 35px #38495910}h1{margin:0 0 8px;font-size:28px}p{color:#64748b}.field{display:grid;gap:8px;margin:20px 0}.field>span{font-weight:600}.field small{color:#64748b}input,textarea,select{font:inherit;width:100%;padding:11px 12px;border:1px solid #cbd5e1;border-radius:9px;background:white;color:#384959}.options{display:grid;gap:9px}.options label,.check{display:flex;gap:9px;align-items:center}.options input,.check input{width:auto}.two{display:grid;grid-template-columns:1fr 1fr;gap:10px}.static{padding:12px;background:#f8fafc;border-radius:8px}.upload-warning{background:#fff7ed;color:#9a3412;padding:12px;border-radius:8px}.btn{background:#6A89A7;color:#fff;border:0;border-radius:10px;padding:12px 18px;font:inherit;cursor:pointer;width:100%;margin-top:8px}@media(max-width:600px){.wrap{margin:10px auto;padding:10px}.card{padding:18px}.two{grid-template-columns:1fr}}</style></head><body><main class="wrap"><section class="card"><p>DIBIAA HUB · SUPPORT</p><h1>${htmlEscape(panel.title)}</h1><p>${htmlEscape(panel.description||'Please complete this form to open a ticket.')}</p><form method="post" action="/ticket-form/${htmlEscape(req.params.token)}">${uploadWarning}${controls}<button class="btn" type="submit">Submit and Open Ticket</button></form></section></main></body></html>`);
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
    const createOptions={name:channelName,type:ChannelType.GuildText,topic:buildTicketTopic(panel, member.user),permissionOverwrites:overwrites};
    const category=String(panel.settings?.ticket_category_id||'');if(category&&/^\d+$/.test(category))createOptions.parent=category;
    const ticketChannel=await guild.channels.create(createOptions);
    recordEvent('ticket_created', guild.id, member.id, member.user.username, 'ticket', ticketChannel.id, {owner_discord_id:panel.owner_discord_id});
    const answerText=answers.join('\n\n')||'No answers provided.';
    const embed=new EmbedBuilder().setTitle(String(panel.title||'Support Ticket').slice(0,256)).setDescription(answerText.slice(0,4000)).setColor(/^#[0-9a-fA-F]{6}$/.test(String(panel.settings?.panel_colour||''))?Number.parseInt(String(panel.settings.panel_colour).slice(1),16):BRAND_COLOUR).addFields({name:'Opened by',value:`<@${member.id}>`,inline:true},{name:'Panel ID',value:String(panel.id),inline:true}).setTimestamp();
    const buttons=[];
    if(!(panel.settings?.hide_close_button||panel.settings?.allow_user_close===0)){buttons.push(new ButtonBuilder().setCustomId('dh_close:'+ticketChannel.id).setLabel('Close').setEmoji('🔒').setStyle(ButtonStyle.Danger));buttons.push(new ButtonBuilder().setCustomId('dh_closereason:'+ticketChannel.id).setLabel('Close With Reason').setEmoji('🔒').setStyle(ButtonStyle.Danger));}
    if(!panel.settings?.hide_claim_button)buttons.push(new ButtonBuilder().setCustomId(`dh_claim:${ticketChannel.id}:${panel.id}`).setLabel('Claim Ticket').setStyle(ButtonStyle.Primary));
    const supportMention=panel.settings?.mention_support&&roleId?`<@&${roleId}> `:'';
    await ticketChannel.send({content:`${supportMention}<@${member.id}>`,embeds:[embed],components:buttons.length?[new ActionRowBuilder().addComponents(buttons)]:[],allowedMentions:{users:[member.id],roles:supportMention?[roleId]:[]}});
    usedFormTokens.add(req.params.token);
    try { await saveToWebsite({action:'ticket_create',title:String(panel.title||'Support Ticket'),description:answerText,discord_user_id:member.id,user_name:member.user.username,discord_channel_id:ticketChannel.id,guild_id:guild.id,owner_discord_id:panel.owner_discord_id,panel_id:String(panel.id),panel_title:String(panel.title||'')}); } catch (error) { console.error('Web form ticket DB sync failed:',error.message); }
    return res.type('html').send(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Ticket opened</title><style>body{font:18px/1.6 Lora,Georgia,serif;background:#F3F8FE;color:#384959;padding:24px}.card{max-width:600px;margin:8vh auto;background:#fff;padding:28px;border-radius:16px}a{color:#6A89A7}</style></head><body><main class="card"><h1>Ticket opened successfully</h1><p>Your ticket channel is <a href="https://discord.com/channels/${guild.id}/${ticketChannel.id}">#${htmlEscape(ticketChannel.name)}</a>.</p><p>You can return to Discord now.</p></main></body></html>`);
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
      if (!channel || !channel.isTextBased() || !channel.topic ||
          !channel.topic.includes('Dibiaa ticket | Owner ID:')) continue;
      const ownerMatch = channel.topic.match(/Owner ID:\s*(\d+)/);
      if (!ownerMatch || ownerMatch[1] !== ownerId) continue;
      const userMatch = channel.topic.match(/User ID:\s*(\d+)/);
      if (!userMatch) continue;
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
      let userName = channel.topic.match(/User Name:\s*([^|]+)/)?.[1]?.trim() || '';
      if (!userName && userMatch) { try { userName = (await guild.members.fetch(userMatch[1])).user.username; } catch {} }
      const topic = channel.topic;
      const panelId = ticketTopicValue(topic, 'Panel');
      tickets.push({
        panel_id: /^\d+$/.test(panelId) ? panelId : '',
        panel_title: panelCache.get(panelId)?.title || '',
        close_by: ticketTopicValue(topic, 'Closed By'),
        close_by_name: ticketTopicValue(topic, 'Closed Name'),
        close_reason: ticketTopicValue(topic, 'Close Reason'),
        closed_at: ticketTopicValue(topic, 'Closed At') ? ticketTopicValue(topic, 'Closed At').slice(0, 19).replace('T', ' ') : '',
        archive_pending: ticketTopicValue(topic, 'Archive Pending') === '1',
        title: embedTitle, user_name: userName, owner_discord_id: ownerId,
        description: messageDescription || 'Ticket created in Discord.',
        discord_user_id: userMatch[1],
        discord_channel_id: channel.id,
        guild_id: guildId,
        status: channel.name.startsWith('closed-') ? 'closed' : 'open',
        claimed_by: channel.topic.match(/Claimed By:\s*(\d+)/)?.[1] || '',
        claimed_by_name: channel.topic.match(/Claimed Name:\s*([^|]+)/)?.[1]?.trim() || '',
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
    const ownerMatch = String(channel?.topic || '').match(/Owner ID:\s*(\d+)/);
    if (!channel || !channel.isTextBased() || !ownerMatch || ownerMatch[1] !== ownerId) return res.status(404).json({ ok:false, error:'Ticket not found for this owner/server' });
    const messages = (await fetchAllMessages(channel)).map(serializeMessage);
    return res.json({ok:true,guild_id:guildId,channel_id:channelId,messages});
  } catch (error) { console.error('Ticket transcript fetch failed:',error.message); return res.status(502).json({ok:false,error:'Could not fetch ticket transcript'}); }
});

// Called by the website after it has stored the conversation of a ticket that the bot
// closed while the website was unreachable. Only then is the Discord channel removed.
app.post('/tickets/:channelId/archive', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.body?.guild_id || ''), ownerId = String(req.body?.owner_discord_id || ''), channelId = String(req.params.channelId || '');
  if (!/^\d{15,22}$/.test(guildId) || !/^\d{15,22}$/.test(ownerId) || !/^\d{15,22}$/.test(channelId)) return res.status(400).json({ ok: false, error: 'Valid guild, owner and channel IDs required' });
  try {
    const guild = await client.guilds.fetch(guildId);
    const channel = await guild.channels.fetch(channelId).catch(() => null);
    if (!channel) return res.json({ ok: true, already_removed: true });
    const topic = String(channel.topic || '');
    if (ticketTopicValue(topic, 'Owner ID') !== ownerId || ticketTopicValue(topic, 'Archive Pending') !== '1') {
      return res.status(409).json({ ok: false, error: 'This channel is not a closed ticket waiting for archive.' });
    }
    await channel.delete('Ticket transcript stored by Dibiaa Hub; archiving closed ticket');
    recordEvent('ticket_archived', guildId, '', 'Dibiaa Bot', 'ticket', channelId, { owner_discord_id: ownerId });
    return res.json({ ok: true });
  } catch (error) {
    console.error('Ticket archive failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not remove the closed ticket channel' });
  }
});

// Ratings that could not be pushed to the website are kept here until the website pulls them.
const pendingRatings = [];
app.get('/ratings/pending', (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.query.guild_id || ''), ownerId = String(req.query.owner_discord_id || '');
  const out = [];
  for (let i = pendingRatings.length - 1; i >= 0; i--) {
    const r = pendingRatings[i];
    if (r.guild_id === guildId && r.owner_discord_id === ownerId) { out.push(r); pendingRatings.splice(i, 1); }
  }
  return res.json({ ok: true, ratings: out });
});

// Discord roles for Staff & Teams.
app.get('/guilds/:guildId/roles', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.params.guildId || '');
  if (!/^\d{15,22}$/.test(guildId)) return res.status(400).json({ ok: false, error: 'Valid guild ID required' });
  try {
    const guild = await client.guilds.fetch(guildId);
    const roles = await guild.roles.fetch();
    return res.json({ ok: true, roles: [...roles.values()].filter(r => !r.managed && r.id !== guild.id)
      .sort((a, b) => b.position - a.position).map(r => ({ id: r.id, name: r.name, color: r.hexColor, position: r.position, members: r.members?.size ?? null })) });
  } catch (error) {
    console.error('Role lookup failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not load Discord roles. Check that the bot is in this server.' });
  }
});

// Members holding a role (needs the Server Members privileged intent).
app.get('/guilds/:guildId/members', async (req, res) => {
  if (!authorized(req)) return res.status(401).json({ ok: false, error: 'Unauthorized' });
  const guildId = String(req.params.guildId || ''), roleId = String(req.query.role_id || '');
  if (!/^\d{15,22}$/.test(guildId) || !/^\d{15,22}$/.test(roleId)) return res.status(400).json({ ok: false, error: 'Valid guild and role IDs required' });
  try {
    const guild = await client.guilds.fetch(guildId);
    const role = await guild.roles.fetch(roleId);
    if (!role) return res.status(404).json({ ok: false, error: 'Role not found' });
    await guild.members.fetch({ time: 15000 }).catch(() => null);
    const members = [...role.members.values()].slice(0, 500).map(m => ({
      id: m.id, username: m.user.username, display_name: m.displayName, avatar: m.user.displayAvatarURL({ size: 64 }),
      roles: [...m.roles.cache.values()].filter(r => r.id !== guild.id).map(r => ({ id: r.id, name: r.name }))
    }));
    return res.json({ ok: true, members });
  } catch (error) {
    console.error('Member lookup failed:', error.message);
    return res.status(502).json({ ok: false, error: 'Could not load role members. Enable the Server Members Intent for the bot.' });
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
    const colourText = /^#[0-9a-fA-F]{6}$/.test(String(safeSettings.panel_colour || '')) ? String(safeSettings.panel_colour) : BRAND_HEX;
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
    topic: buildTicketTopic(panel, interaction.user),
    permissionOverwrites: overwrites
  };

  const panelCategoryId = String(panel.settings?.ticket_category_id || ticketCategoryId || '');
  if (panelCategoryId && /^\d+$/.test(panelCategoryId)) options.parent = panelCategoryId;

  const channel = await guild.channels.create(options);
  recordEvent('ticket_created', guild.id, interaction.user.id, interaction.user.username, 'ticket', channel.id, {owner_discord_id:panel.owner_discord_id});
  const embed = new EmbedBuilder()
    .setTitle(String(panel.title || 'Support Ticket').slice(0, 256))
    .setDescription(description.slice(0, 4000))
    .setColor(/^#[0-9a-fA-F]{6}$/.test(String(panel.settings?.panel_colour || '')) ? Number.parseInt(String(panel.settings.panel_colour).slice(1), 16) : BRAND_COLOUR)
    .addFields(
      { name: 'Opened by', value: `<@${interaction.user.id}>`, inline: true },
      { name: 'Panel ID', value: String(panel.id), inline: true }
    )
    .setTimestamp();

  const ticketButtons = [];
  if (!(panel.settings?.hide_close_button || panel.settings?.allow_user_close === 0)) {
    ticketButtons.push(new ButtonBuilder()
      .setCustomId('dh_close:' + channel.id)
      .setLabel('Close')
      .setEmoji('🔒')
      .setStyle(ButtonStyle.Danger));
    ticketButtons.push(new ButtonBuilder()
      .setCustomId('dh_closereason:' + channel.id)
      .setLabel('Close With Reason')
      .setEmoji('🔒')
      .setStyle(ButtonStyle.Danger));
  }
  if (!panel.settings?.hide_claim_button) {
    ticketButtons.push(new ButtonBuilder()
      .setCustomId('dh_claim:' + channel.id + ':' + panel.id)
      .setLabel('Claim Ticket')
      .setStyle(ButtonStyle.Primary));
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

function canCloseTicket(interaction, channel) {
  const topic = String(channel.topic || '');
  const ownerId = ticketTopicValue(topic, 'Owner ID');
  const ticketUser = ticketTopicValue(topic, 'User ID');
  const panel = panelCache.get(ticketTopicValue(topic, 'Panel')) || {};
  const roleId = String(panel.settings?.support_role_id || ticketTopicValue(topic, 'Support Role ID') || '');
  const isSupport = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) || Boolean(roleId && interaction.member?.roles?.cache?.has(roleId));
  if (!isSupport && interaction.user.id !== ticketUser) return { ok: false, error: 'Only the ticket owner or a support team member can close this ticket.' };
  if (!/^\d{15,22}$/.test(ownerId)) return { ok: false, error: 'This ticket is missing its workspace owner reference. Please contact an administrator; the channel was not deleted.' };
  return { ok: true };
}

async function sendFeedbackRequest(guild, topic, channelId) {
  if (ticketTopicValue(topic, 'Feedback') !== '1') return;
  const userId = ticketTopicValue(topic, 'User ID'), ownerId = ticketTopicValue(topic, 'Owner ID');
  if (!/^\d{15,22}$/.test(userId)) return;
  try {
    const user = await client.users.fetch(userId);
    const row = new ActionRowBuilder().addComponents([1, 2, 3, 4, 5].map(n =>
      new ButtonBuilder().setCustomId(`dh_rate:${guild.id}:${channelId}:${ownerId}:${n}`).setLabel('⭐'.repeat(n)).setStyle(n >= 4 ? ButtonStyle.Success : ButtonStyle.Secondary)));
    const embed = new EmbedBuilder().setColor(BRAND_COLOUR).setTitle('How was your support experience?')
      .setDescription(`Your ticket in **${guild.name}** has been closed. Please rate the help you received.`);
    await user.send({ embeds: [embed], components: [row] });
  } catch (error) { console.warn('Feedback DM could not be sent (user may have DMs disabled):', error.message); }
}

/**
 * Closes a ticket: saves the conversation to the website, posts the TXT transcript, asks for feedback
 * and deletes the channel. If the website cannot be reached the channel is NOT deleted; it is renamed
 * closed-*, locked, and marked "Archive Pending" so the website can import it on its next sync.
 */
async function closeTicketChannel(channel, actor, reason, notify = null) {
  const topic = String(channel.topic || '');
  const guild = channel.guild;
  const ownerId = ticketTopicValue(topic, 'Owner ID');
  const ticketUser = ticketTopicValue(topic, 'User ID');
  const panelId = ticketTopicValue(topic, 'Panel');
  const panel = panelCache.get(panelId) || {};
  const closeReason = String(reason || '').trim() || 'No reason specified';
  if (ticketTopicValue(topic, 'Archive Pending') === '1') return { ok: true, message: 'This ticket is already closed and is waiting for the dashboard to archive it.' };
  let messages = [];
  try { messages = (await fetchAllMessages(channel)).map(serializeMessage); }
  catch (error) { console.error('Transcript read failed:', error.message); return { ok: false, message: 'The ticket conversation could not be read, so the ticket was not closed. Check the bot\'s Read Message History permission.' }; }
  const firstBotEmbed = messages.find(m => m.author_id === client.user.id && m.embeds.length)?.embeds[0];
  const payload = {
    action: 'ticket_snapshot', owner_discord_id: ownerId, guild_id: guild.id, discord_channel_id: channel.id, discord_user_id: ticketUser,
    user_name: ticketTopicValue(topic, 'User Name'), title: firstBotEmbed?.title || channel.name.replace(/^closed-/, '').replace(/-/g, ' '),
    panel_id: /^\d+$/.test(panelId) ? panelId : '', panel_title: panel.title || firstBotEmbed?.title || '',
    opened_at: ticketTopicValue(topic, 'Opened At') || channel.createdAt.toISOString(),
    status: 'closed', claimed_by: ticketTopicValue(topic, 'Claimed By'), claimed_by_name: ticketTopicValue(topic, 'Claimed Name'),
    close_by: actor.id, close_by_name: actor.username, close_reason: closeReason, messages
  };
  let snapshot = null;
  try { snapshot = await saveToWebsite(payload); } catch (error) { console.error('Ticket snapshot could not be saved to the website:', error.message); }

  const transcriptChannelId = String(panel.settings?.transcript_channel_id || ticketTopicValue(topic, 'Transcript Channel ID') || '');
  if (/^\d{15,22}$/.test(transcriptChannelId)) {
    try {
      const transcriptChannel = await guild.channels.fetch(transcriptChannelId).catch(() => null);
      if (transcriptChannel?.isTextBased()) {
        const lines = messages.map(m => `[${m.created_at}] ${m.author_name} (${m.author_id})\n${m.content}${m.embeds.length ? '\n' + m.embeds.map(e => [e.title, e.description].filter(Boolean).join('\n')).join('\n') : ''}${m.attachments.length ? '\nAttachments: ' + m.attachments.map(a => a.url).join(', ') : ''}`).join('\n\n');
        const file = new AttachmentBuilder(Buffer.from(`DIBIAA HUB TICKET TRANSCRIPT\nTicket Channel: ${channel.name} (${channel.id})\nClosed By: ${actor.username}\nClose Reason: ${closeReason}\n\n${lines}`, 'utf8'), { name: `ticket-${channel.id}-transcript.txt` });
        const embed = new EmbedBuilder().setColor(BRAND_COLOUR).setTitle(`Ticket closed · #${channel.name}`)
          .addFields({ name: 'Opened by', value: ticketUser ? `<@${ticketUser}>` : 'Unknown', inline: true }, { name: 'Closed by', value: `<@${actor.id}>`, inline: true }, { name: 'Reason', value: closeReason.slice(0, 1000) })
          .setTimestamp();
        if (snapshot?.ticket_code) embed.setFooter({ text: `Reference ${snapshot.ticket_code}` });
        await transcriptChannel.send({ embeds: [embed], files: [file], allowedMentions: { parse: [] } });
      }
    } catch (error) { console.error('Transcript channel post failed:', error.message); }
  }
  recordEvent('ticket_closed', guild.id, actor.id, actor.username, 'ticket', channel.id, { owner_discord_id: ownerId, reason: closeReason });
  await sendFeedbackRequest(guild, topic, channel.id);

  if (snapshot) {
    const message = `Ticket closed. ${snapshot.ticket_code ? `Reference: ${snapshot.ticket_code}. ` : ''}The transcript was saved to the dashboard.`;
    // Reply before the channel disappears, otherwise the reply has nowhere to go.
    if (notify) await notify(message).catch(() => {});
    await channel.delete(`Ticket closed by ${actor.username}; transcript saved to Dibiaa Hub`).catch(error => console.error('Ticket channel delete failed:', error.message));
    return { ok: true, message, notified: Boolean(notify) };
  }
  // Website unreachable: keep the conversation in Discord until the dashboard imports it.
  try {
    const closedAt = new Date().toISOString();
    const cleaned = topic.replace(/\s*\|\s*(Closed By|Closed Name|Close Reason|Closed At|Archive Pending):[^|]*/g, '');
    const nextTopic = `${cleaned} | Closed By: ${actor.id} | Closed Name: ${topicSafe(actor.username).slice(0, 40)} | Closed At: ${closedAt} | Archive Pending: 1 | Close Reason: ${topicSafe(closeReason)}`.slice(0, 1024);
    await channel.setTopic(nextTopic);
    if (!channel.name.startsWith('closed-')) await channel.setName(('closed-' + channel.name).slice(0, 100)).catch(() => {});
    if (/^\d{15,22}$/.test(ticketUser)) await channel.permissionOverwrites.edit(ticketUser, { SendMessages: false }).catch(() => {});
    await channel.send({ embeds: [new EmbedBuilder().setColor(BRAND_COLOUR).setTitle('🔒 Ticket closed')
      .setDescription(`Closed by <@${actor.id}>.\n**Reason:** ${closeReason.slice(0, 1000)}\n\nThis channel will be removed automatically once the Dibiaa Hub dashboard has saved its transcript.`)], allowedMentions: { parse: [] } });
  } catch (error) { console.error('Could not mark ticket as closed:', error.message); }
  return { ok: true, message: 'Ticket closed. The dashboard could not be reached right now, so the channel was locked and kept; it will be archived automatically on the next dashboard sync.' };
}

// Auto-close: checks inactive tickets every 10 minutes using the "Auto Close Hours" saved in each ticket topic.
async function runAutoClose() {
  if (!client.isReady()) return;
  for (const guild of client.guilds.cache.values()) {
    let channels;
    try { channels = await guild.channels.fetch(); } catch { continue; }
    for (const channel of channels.values()) {
      try {
        if (!channel?.isTextBased?.() || !channel.topic?.includes('Dibiaa ticket') || channel.name.startsWith('closed-')) continue;
        const panel = panelCache.get(ticketTopicValue(channel.topic, 'Panel'));
        const hours = Number(ticketTopicValue(channel.topic, 'Auto Close Hours') || (Number(panel?.settings?.auto_close) === 1 ? panel.settings.auto_close_hours || 72 : 0));
        if (!hours) continue;
        const lastActivity = channel.lastMessageId ? SnowflakeUtil.timestampFrom(channel.lastMessageId) : channel.createdTimestamp;
        if (Date.now() - lastActivity < hours * 3600 * 1000) continue;
        await closeTicketChannel(channel, client.user, `Automatically closed after ${hours} hour(s) without activity`);
      } catch (error) { console.error('Auto-close check failed for channel', channel?.id, error.message); }
    }
  }
}
setInterval(() => { runAutoClose().catch(error => console.error('Auto-close run failed:', error.message)); }, 10 * 60 * 1000).unref();

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
          ch.topic.includes(`User ID: ${interaction.user.id}`) &&
          ch.topic.includes(`Panel: ${panelId}`) &&
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
      const supportRoleId = String(panel?.settings?.support_role_id || topic.match(/Support Role ID:\s*(\d+)/)?.[1] || '');
      const hasSupportRole = Boolean(supportRoleId && interaction.member?.roles?.cache?.has(supportRoleId));
      const canClaim = interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels) || hasSupportRole;
      if (!channel || !canClaim) {
        await interaction.reply({ content: 'Only support team members can claim tickets.', ephemeral: true });
        return;
      }
      const existing = topic.match(/Claimed By:\s*(\d+)/)?.[1] || '';
      const isUnclaim = existing === interaction.user.id;
      if (existing && !isUnclaim) {
        await interaction.reply({ content: `This ticket is already claimed by <@${existing}>.`, ephemeral: true });
        return;
      }
      if (existing && !isUnclaim && !interaction.memberPermissions?.has(PermissionFlagsBits.ManageChannels)) return;
      try {
        const cleaned = topic.replace(/\s*\|\s*Claimed By:\s*\d+/,'').replace(/\s*\|\s*Claimed Name:\s*[^|]*/,'').trim();
        const nextTopic = isUnclaim ? cleaned : `${cleaned} | Claimed By: ${interaction.user.id} | Claimed Name: ${interaction.user.username}`;
        await channel.setTopic(nextTopic.slice(0,1024));
        const rows = interaction.message.components.map(row => {
          const nextRow = ActionRowBuilder.from(row);
          nextRow.setComponents(nextRow.components.map(component => {
            const button = ButtonBuilder.from(component);
            if (button.data.custom_id?.startsWith('dh_claim:')) {
              button.setLabel(isUnclaim ? 'Claim Ticket' : 'Unclaim Ticket');
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

    if (interaction.isButton() && /^dh_close(yes|reason)?:/.test(interaction.customId)) {
      const [kind] = interaction.customId.split(':');
      const channel = interaction.channel;
      if (!channel || !channel.isTextBased() || !interaction.guild || !String(channel.topic || '').includes('Dibiaa ticket')) {
        await interaction.reply({ content: 'Ticket channel not found.', ephemeral: true });
        return;
      }
      const check = canCloseTicket(interaction, channel);
      if (!check.ok) { await interaction.reply({ content: check.error, ephemeral: true }); return; }
      if (kind === 'dh_closereason') {
        const modal = new ModalBuilder().setCustomId('dh_closemodal:' + channel.id).setTitle('Close ticket');
        modal.addComponents(new ActionRowBuilder().addComponents(new TextInputBuilder()
          .setCustomId('reason').setLabel('Reason for closing').setStyle(TextInputStyle.Paragraph)
          .setRequired(true).setMaxLength(500).setPlaceholder('e.g. Issue resolved, replacement delivered')));
        await interaction.showModal(modal);
        return;
      }
      const wantsConfirmation = kind === 'dh_close' && ticketTopicValue(channel.topic, 'Confirm Close') !== '0';
      if (wantsConfirmation) {
        const row = new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId('dh_closeyes:' + channel.id).setLabel('Close').setEmoji('🔒').setStyle(ButtonStyle.Danger),
          new ButtonBuilder().setCustomId('dh_closereason:' + channel.id).setLabel('Close With Reason').setEmoji('🔒').setStyle(ButtonStyle.Danger));
        await interaction.reply({ content: 'Are you sure you want to close this ticket? The conversation will be saved as a transcript.', components: [row], ephemeral: true });
        return;
      }
      await interaction.deferReply({ ephemeral: true });
      const result = await closeTicketChannel(channel, interaction.user, '', m => interaction.editReply(m));
      if (!result.notified) await interaction.editReply(result.message).catch(() => {});
      return;
    }

    if (interaction.isModalSubmit() && interaction.customId.startsWith('dh_closemodal:')) {
      const channel = interaction.channel;
      if (!channel || !interaction.guild) { await interaction.reply({ content: 'Ticket channel not found.', ephemeral: true }); return; }
      const check = canCloseTicket(interaction, channel);
      if (!check.ok) { await interaction.reply({ content: check.error, ephemeral: true }); return; }
      await interaction.deferReply({ ephemeral: true });
      const reason = interaction.fields.getTextInputValue('reason').trim().slice(0, 500);
      const result = await closeTicketChannel(channel, interaction.user, reason, m => interaction.editReply(m));
      if (!result.notified) await interaction.editReply(result.message).catch(() => {});
      return;
    }

    if (interaction.isButton() && interaction.customId.startsWith('dh_rate:')) {
      const [, guildId, channelId, ownerId, value] = interaction.customId.split(':');
      const rating = Math.max(1, Math.min(5, Number(value) || 0));
      const payload = { action: 'ticket_rating', guild_id: guildId, discord_channel_id: channelId, owner_discord_id: ownerId, discord_user_id: interaction.user.id, rating };
      try { await saveToWebsite(payload); }
      catch (error) {
        console.error('Rating could not be saved to the website; queued for the next dashboard sync:', error.message);
        pendingRatings.push({ ...payload, created_at: new Date().toISOString() });
        if (pendingRatings.length > 2000) pendingRatings.shift();
      }
      await interaction.update({ content: `Thank you! You rated your support experience ${'⭐'.repeat(rating)} (${rating}/5).`, embeds: [], components: [] }).catch(() => {});
      return;
    }

    if (interaction.isModalSubmit() && interaction.customId.startsWith('dh_submit:')) {
      const panelId = interaction.customId.slice('dh_submit:'.length);
      let panel = panelCache.get(panelId);
      if (!panel && interaction.message) {
        try { panel = await recoverPanelFromMessage({ panel_id: panelId, guild_id: interaction.guildId, channel_id: interaction.message.channelId, message_id: interaction.message.id }); } catch {}
      }

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
          'The ticket channel could not be created. Please ask an admin to check the bot\'s Manage Channels permission and the panel category/role settings.'
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
          owner_discord_id: panel.owner_discord_id,
          panel_id: String(panel.id),
          panel_title: String(panel.title || '')
        });
        databaseSaved = true;
      } catch (error) {
        console.error('Ticket created in Discord, but website DB sync failed:', error.message);
      }

      if (!databaseSaved) console.warn('Ticket channel created; it will be imported on the next dashboard sync.');
      await interaction.editReply(`Your ticket has been created: <#${ticketChannel.id}>`);
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
      const userId = channel.topic.match(/User ID: (\d+)/)?.[1];
      const panelId = channel.topic.match(/Panel: (\d+)/)?.[1];
      if (userId !== member.id || !panelId || String(channel.name || '').startsWith('closed-')) continue;
      const panel = panelCache.get(panelId);
      if (!panel?.settings?.close_on_user_leave) continue;
      await closeTicketChannel(channel, client.user, 'Automatically closed because the ticket creator left the server');
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
