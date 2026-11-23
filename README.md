# Dibiaa Hub Discord Ticket Bot — patched build

## Fixes in this build
- Adds authenticated `/guilds/:guildId/roles` and `/guilds/:guildId/members` endpoints used by the Staff & Teams page.
- Staff & Teams member lookup fetches real guild members by assigned role and returns clear errors when Discord blocks member access.
- Panel Builder selects a Support Team. All roles assigned to that team are recognized for claim/close permissions. Ticket creation does not ping support roles. Where team size permits, access is granted to individual team members so role chips do not clutter the ticket channel header.
- Supports multiple independent support teams per Discord server and multiple Discord roles inside each team.
- Improves Staff & Teams spacing, responsive layout, and form sizing.
- Panel publish no longer reports a false failure just because Render cannot call the InfinityFree API.
- Panel questions are cached in the bot when the website publishes the panel.
- The Create Ticket button opens the modal from cached panel data.
- Submitting the form creates a private Discord ticket channel.
- Website database sync is best-effort and logs the exact reason if InfinityFree blocks the request.
- Ticket channels are named from the panel title with a per-panel sequence, for example `maintenance-1`, `maintenance-2`.
- Each panel has its own sequence, persisted in the Discord panel message so it survives bot restarts.
- Adds a **Reset Ticket ID** action to the Panels page; the next ticket for that panel starts at #1.
- Ticket channel topics are human-readable and no longer expose raw owner/user/role/transcript IDs. Private metadata is stored in a hidden embed footer.
- Claim posts a visible status message. Unclaim removes that message and restores the Claim button.
- Close saves a transcript to the website database, configured transcript channel, or ticket opener DM before deleting the ticket channel.
- Ticket channels are named from the panel title with a per-panel sequence, for example `maintenance-1`, `maintenance-2`.
- Each panel has its own sequence, persisted in the Discord panel message so it survives bot restarts.
- Adds a **Reset Ticket ID** action to the Panels page; the next ticket for that panel starts at #1.
- Ticket channel topics are human-readable and no longer expose raw owner/user/role/transcript IDs. Private metadata is stored in a hidden embed footer.
- Claim posts a visible status message. Unclaim removes that message and restores the Claim button.
- Close saves a transcript to the website database, configured transcript channel, or ticket opener DM before deleting the ticket channel.
- Adds a Close Ticket button and optional category/support role configuration.

## Render environment variables
Required:
- `DISCORD_TOKEN`
- `API_KEY` (must match `BOT_API_KEY` in website `includes/config.php`)
- `WEBSITE_API_URL` (for example `https://dibiaa.free.nf/api/bot.php`)
- `DISCORD_CLIENT_ID`
- `DISCORD_CLIENT_SECRET`
- `DISCORD_REDIRECT_URI` = `https://dibiaa.free.nf/discord-callback.php` (must exactly match the Discord Developer Portal OAuth redirect URI)
- `PUBLIC_BASE_URL` = the public HTTPS URL of this Render web service (for example, `https://dibiaa-bot.onrender.com`)

Optional:
- `TICKET_CATEGORY_ID` = Discord category ID where new ticket channels should be created
- `SUPPORT_ROLE_ID` = support team role ID to grant access and mention

## Deploy
1. Replace the current Render bot project files with this ZIP's contents.
2. Keep your secret values in Render Environment, not in source code.
3. Deploy the service.
4. Re-open the Ticket Panel Builder and publish the panel again. Re-publishing is required because the bot caches the panel questions in memory.
5. Test Create Ticket. The bot should open the form and create a private ticket channel.

## Important database limitation
The logs you shared show InfinityFree returns an HTML page containing `/aes.js` to requests made from Render. InfinityFree's free-hosting security layer blocks automated/server-to-server API calls; the API key or PHP changes cannot disable this host-level protection. This build makes Discord ticket creation work without that API call being mandatory, but ticket records may not appear in the website's MySQL dashboard until the API/database is moved to a host that supports server-to-server API access or an external storage bridge is configured.

## Security
Your previous ZIP included credentials. Rotate the Discord client secret, database password, and API key, then update the Render environment variables and website config. Do not commit secrets to GitHub.

## Required Discord setting for live member lists
1. Open https://discord.com/developers/applications and select the bot application.
2. Open **Bot** in the left menu.
3. Under **Privileged Gateway Intents**, enable **Server Members Intent**.
4. Save changes, then restart/redeploy the Render service.
5. Confirm the bot is still in the selected server and has the required server permissions.

The bot code already requests `GatewayIntentBits.GuildMembers`; enabling the portal toggle is also required. The website's Roles endpoint does not depend on this privileged intent, but live member lists do.

## Website deployment
Upload the contents of the `htdocs/` folder to the website's `htdocs` directory, replacing the old PHP files. Keep your private `includes/config.local.php` file on the server; this update deliberately does not include real credentials. If it does not exist, copy `includes/config.local.example.php` to `includes/config.local.php` and enter your current database, Discord OAuth, and API settings.

## Important security note
The previous uploaded website configuration contained live credentials. They have been replaced with placeholders in this ZIP. Rotate the database password, Discord application client secret, and API key before deploying, then update the website's private `includes/config.local.php` and Render environment variables with the new values. Never upload `config.local.php` or `.env` into a shared ZIP or Git repository.
