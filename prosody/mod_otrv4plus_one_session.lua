-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
-- Copyright (C) 2025-2026 muc111
--
-- mod_otrv4plus_one_session: at most `max_resources` signed-in sessions per
-- account (default 1), and a NEW sign-in signs the OLDEST one out instead of
-- being refused.
--
-- Why not mod_c2s_limit_sessions: it refuses the new sign-in. Over I2P a
-- phone that loses its connection leaves its old session on the server for
-- minutes, so the owner reconnecting was locked out by their own dead
-- session -- and anyone who signed in first with a stolen password locked
-- the owner out. Here the newest sign-in wins: the owner always gets back
-- in, and the session pushed out is told why (stream error `conflict`).
-- OTRv4+ clients do not reconnect after that, so two devices cannot take
-- turns throwing each other out; they tell the user, who can change the
-- password. See docs/SECURITY_SESSIONS.md.

local max_resources = module:get_option_number("max_resources", 1);
if max_resources < 1 then max_resources = 1; end

local sessions = prosody.hosts[module.host].sessions;

module:hook("pre-resource-bind", function(event)
	local session = event.session;
	local account = sessions[session.username];
	if not account then
		return; -- no other session
	end
	local others = {};
	for _, other in pairs(account.sessions) do
		if other ~= session then
			others[#others + 1] = other;
		end
	end
	local excess = #others - (max_resources - 1);
	if excess <= 0 then
		return;
	end
	-- Oldest first.
	table.sort(others, function (a, b)
		return (a.conntime or 0) < (b.conntime or 0);
	end);
	for i = 1, excess do
		local old = others[i];
		module:log("info", "Signing out %s: the account signed in again",
			old.full_jid or "an older session");
		old:close({ condition = "conflict",
			text = "Replaced by a newer sign-in of this account" });
	end
end, -1);
