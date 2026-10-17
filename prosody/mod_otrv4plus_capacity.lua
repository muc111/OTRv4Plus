-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
-- Copyright (C) 2025-2026 muc111
--
-- mod_otrv4plus_capacity: hard limits that keep one machine within what it
-- can carry, and keep account creation from being used to flood it.
--
--   max_online_users           = 2000  -- people signed in at once (0: none)
--   login_rate                 = 10    -- new sign-ins let in per second (0: none)
--   login_burst                = 40    -- ...of which this many at once
--   max_registrations_per_hour = 30    -- new accounts, server-wide (0: none)
--   max_registered_users       = 0     -- accounts in total (0: none)
--
-- WHY SERVER-WIDE, NOT PER ADDRESS. Over I2P every client reaches Prosody
-- from i2pd's local end, 127.0.0.1: Prosody never sees who is connecting, so
-- a per-IP limit is one shared limit by accident. These are shared on
-- purpose, and say so. (Per-destination limits belong to i2pd: see
-- SERVER_HARDENING.md.)
--
-- Someone already signed in who signs in again (a reconnect, or replacing a
-- session, mod_otrv4plus_one_session) is never refused for being one too
-- many: they are not a new person online.

local usermanager = require "core.usermanager";

local max_online = module:get_option_number("max_online_users", 2000);
local per_hour = module:get_option_number("max_registrations_per_hour", 30);
local max_registered = module:get_option_number("max_registered_users", 0);

local login_rate = module:get_option_number("login_rate", 10);
local login_burst = module:get_option_number("login_burst", 40);

local host_sessions = prosody.hosts[module.host].sessions;

-- SIGN-IN PACING (owner, 2026-10-17: "schedule them at the server for a
-- smooth login without peaking CPU"). Two thousand phones reconnecting at
-- once after a restart would each cost a TLS handshake, a SCRAM password
-- check and then their rooms and groups, all in the same seconds, on
-- Prosody's one core. A token bucket lets in login_rate new connections a
-- second (login_burst at once); the rest are turned away with
-- resource-constraint "busy" at their FIRST stream features, before TLS or
-- any password work, which costs almost nothing. The apps retry after a
-- randomised delay, so the crowd arrives spread out instead of together.
local now = require "util.time".now;
local tokens, refilled = login_burst, now();

local function admit()
	local t = now();
	tokens = math.min(login_burst, tokens + (t - refilled) * login_rate);
	refilled = t;
	if tokens >= 1 then
		tokens = tokens - 1;
		return true;
	end
	return false;
end

module:hook("stream-features", function (event)
	if login_rate <= 0 then return; end
	local session = event.origin;
	-- Once per connection, at its first features (before STARTTLS).
	if session.type ~= "c2s_unauthed" or session.otrv4plus_admitted then return; end
	if admit() then
		session.otrv4plus_admitted = true;
		return;
	end
	module:log("info", "Sign-ins arriving faster than login_rate = %d/s: "
		.. "one asked to retry", login_rate);
	session:close({ condition = "resource-constraint",
		text = "The server is busy letting people in. Try again in a moment." });
	return true;
end, 1000);

local function online_users()
	local n = 0;
	for _ in pairs(host_sessions) do n = n + 1; end
	return n;
end

-- Before mod_otrv4plus_one_session's hook (-1): a full server refuses a new
-- person before anything else is done for them.
module:hook("pre-resource-bind", function (event)
	if max_online <= 0 then return; end
	local session = event.session;
	if host_sessions[session.username] then
		return; -- already online here: a reconnect, not one more person
	end
	local n = online_users();
	if n >= max_online then
		module:log("warn", "Refused a sign-in: %d people online (max_online_users = %d)",
			n, max_online);
		-- XMPP Guard (mod_xmppguard) shows this as "At capacity".
		module:fire_event("user-limits/refused",
			{ session = session, what = "online", count = n, limit = max_online });
		event.error = { condition = "resource-constraint",
			text = "This server is full: it allows " .. max_online
				.. " people online at once. Try again later." };
		session:close(event.error);
		return false;
	end
end, 10);

-- New accounts in the last hour, oldest first (os.time() seconds).
local recent = {};

local function prune(now)
	local kept = {};
	for _, t in ipairs(recent) do
		if now - t < 3600 then kept[#kept + 1] = t; end
	end
	recent = kept;
end

local function refuse(event, text)
	event.allowed = false;
	event.reason = text;
	event.error = { type = "wait", condition = "resource-constraint", text = text };
end

module:hook("user-registering", function (event)
	local now = os.time();
	prune(now);
	if per_hour > 0 and #recent >= per_hour then
		module:log("warn", "Refused a new account: %d in the last hour "
			.. "(max_registrations_per_hour = %d)", #recent, per_hour);
		refuse(event, "Too many new accounts on this server in the last hour. "
			.. "Try again later.");
		return;
	end
	if max_registered > 0 then
		local n = 0;
		for _ in usermanager.users(module.host) do n = n + 1; end
		if n >= max_registered then
			module:log("warn", "Refused a new account: %d accounts "
				.. "(max_registered_users = %d)", n, max_registered);
			module:fire_event("user-limits/refused", { session = event.session,
				what = "registration", count = n, limit = max_registered });
			refuse(event, "This server is not taking new accounts: it is full.");
			return;
		end
	end
end);

-- Counted once it exists: an attempt that fails (a name already taken)
-- does not use up the hour.
module:hook("user-registered", function ()
	recent[#recent + 1] = os.time();
end);
