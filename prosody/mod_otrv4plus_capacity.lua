-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
-- Copyright (C) 2025-2026 muc111
--
-- mod_otrv4plus_capacity: hard limits that keep one machine within what it
-- can carry, and keep account creation from being used to flood it.
--
--   max_online_users           = 2000  -- people signed in at once (0: none)
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

local host_sessions = prosody.hosts[module.host].sessions;

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
