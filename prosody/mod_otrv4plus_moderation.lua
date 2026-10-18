-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
-- Copyright (C) 2025-2026 muc111
--
-- mod_otrv4plus_moderation: server admins ban accounts for a number of days
-- or for good, lift a ban, see every room on the server -- hidden ones
-- included -- and destroy any room.
-- Owner (2026-10-17): "Alice should be able to ban any user on
-- their user profile ... for set amount of days or Perm ban or unban ...
-- for server admin / mod use only. No one else should see it."
--
-- WHO MAY. The commands are XEP-0050 ad-hoc commands with permission
-- "admin": Prosody offers and runs them for this host's admins (the
-- `admins = { ... }` list) and nobody else. The apps show the controls only
-- when the server lists these commands to the account, and the server
-- decides every use.
--
-- WHAT A BAN DOES. The account's sessions are closed at once with stream
-- error policy-violation, and every later sign-in is refused at resource
-- bind with the same error until the ban ends. The text carries
-- "(until=<unix time>)" -- 0 for permanent -- which the apps read to say
-- when it ends; nothing else in it is relied on. Bans are stored with
-- Prosody's storage (store "otrv4plus_bans"), so they survive a restart.
-- An admin cannot be banned, and nobody can ban themself.
--
--   otrv4plus_muc_host = "conference.<this host>"  -- for "List all rooms"

local jid = require "util.jid";
local usermanager = require "core.usermanager";
local dataforms_new = require "util.dataforms".new;
local adhoc_simple = require "util.adhoc".new_simple_form;
module:depends("adhoc");
local adhoc_new = module:require "adhoc".new;

local bans = module:open_store("otrv4plus_bans");
local host = module.host;
local host_sessions = prosody.hosts[host].sessions;
local muc_host = module:get_option_string("otrv4plus_muc_host", "conference." .. host);

local NS = "https://otrv4plus.i2p/protocol/admin#";
local MAX_DAYS = 3650;

local function is_admin(user_jid)
	local ok, admin = pcall(usermanager.is_admin, user_jid, host);
	return ok and admin;
end

local function ban_text(until_)
	if until_ == 0 then
		return "This account is banned from this server permanently (until=0).";
	end
	return ("This account is banned from this server until %s UTC (until=%d).")
		:format(os.date("!%Y-%m-%d %H:%M", until_), until_);
end

-- The ban on `username`, or nil. An expired ban is removed here.
local function active_ban(username)
	local ban = bans:get(username);
	if not ban then return nil; end
	local until_ = tonumber(ban["until"]) or 0;
	if until_ ~= 0 and until_ <= os.time() then
		bans:set(username, nil);
		return nil;
	end
	return ban, until_;
end

local function close_sessions(username, text)
	local account = host_sessions[username];
	if not account then return 0; end
	local n = 0;
	for _, session in pairs(account.sessions) do
		session:close({ condition = "policy-violation", text = text });
		n = n + 1;
	end
	return n;
end

-- Before every other pre-resource-bind hook (capacity at 10, one_session at
-- -1): a banned account is refused before anything else is done for it.
module:hook("pre-resource-bind", function (event)
	local session = event.session;
	local _, until_ = active_ban(session.username);
	if until_ == nil then return; end
	module:log("info", "Refused a sign-in of a banned account");
	event.error = { condition = "policy-violation", text = ban_text(until_) };
	session:close(event.error);
	return false;
end, 100);

-- The account named in a form, on THIS host, or nil and why not.
local function target(fields)
	local who = jid.prep(fields.accountjid or "");
	if not who then return nil, "That is not an address."; end
	local node, h = jid.split(jid.bare(who));
	if not node or h ~= host then
		return nil, "Only accounts on " .. host .. " can be banned here.";
	end
	return node, jid.bare(who);
end

local account_field = { name = "accountjid", type = "jid-single", required = true,
	label = "Account" };

local ban_form = dataforms_new {
	title = "Ban an account";
	{ name = "FORM_TYPE", type = "hidden", value = NS .. "ban-user" };
	account_field;
	{ name = "days", type = "text-single", label = "Days (0 = permanent)", value = "0" };
	{ name = "reason", type = "text-single", label = "Reason (only admins see it)" };
};

local ban_handler = adhoc_simple(ban_form, function (fields, err, data)
	if err then
		return { status = "completed", error = { message = "The form was not filled in." } };
	end
	local node, bare = target(fields);
	if not node then return { status = "completed", error = { message = bare } }; end
	local actor = jid.bare(data.from);
	if bare == actor then
		return { status = "completed", error = { message = "You cannot ban yourself." } };
	end
	if is_admin(bare) then
		return { status = "completed", error = { message = "An admin cannot be banned." } };
	end
	if not usermanager.user_exists(node, host) then
		return { status = "completed", error = { message = "There is no such account." } };
	end
	local days = tonumber(fields.days or "0");
	if not days or days < 0 or days > MAX_DAYS or days ~= math.floor(days) then
		return { status = "completed",
			error = { message = "Days must be a whole number from 0 (permanent) to " .. MAX_DAYS .. "." } };
	end
	local until_ = days == 0 and 0 or (os.time() + days * 86400);
	bans:set(node, { ["until"] = until_, by = actor, at = os.time(),
		reason = (fields.reason or ""):sub(1, 200) });
	local closed = close_sessions(node, ban_text(until_));
	module:log("warn", "%s banned %s %s", actor, bare,
		days == 0 and "permanently" or ("for " .. days .. " days"));
	return { status = "completed", info = ("Banned %s %s.%s"):format(bare,
		days == 0 and "permanently" or ("until " .. os.date("!%Y-%m-%d %H:%M", until_) .. " UTC"),
		closed > 0 and " They were signed out." or "") };
end);

local unban_form = dataforms_new {
	title = "Lift a ban";
	{ name = "FORM_TYPE", type = "hidden", value = NS .. "unban-user" };
	account_field;
};

local unban_handler = adhoc_simple(unban_form, function (fields, err, data)
	if err then
		return { status = "completed", error = { message = "The form was not filled in." } };
	end
	local node, bare = target(fields);
	if not node then return { status = "completed", error = { message = bare } }; end
	if not active_ban(node) then
		return { status = "completed", info = bare .. " is not banned." };
	end
	bans:set(node, nil);
	module:log("warn", "%s lifted the ban on %s", jid.bare(data.from), bare);
	return { status = "completed", info = "The ban on " .. bare .. " is lifted." };
end);

local status_form = dataforms_new {
	title = "Ban status";
	{ name = "FORM_TYPE", type = "hidden", value = NS .. "ban-status" };
	account_field;
};

local status_result = dataforms_new {
	title = "Ban status";
	{ name = "FORM_TYPE", type = "hidden", value = NS .. "ban-status" };
	{ name = "banned", type = "boolean" };
	{ name = "until", type = "text-single" };
	{ name = "reason", type = "text-single" };
	{ name = "by", type = "jid-single" };
};

local status_handler = adhoc_simple(status_form, function (fields, err)
	if err then
		return { status = "completed", error = { message = "The form was not filled in." } };
	end
	local node, bare = target(fields);
	if not node then return { status = "completed", error = { message = bare } }; end
	local ban, until_ = active_ban(node);
	return { status = "completed", result = { layout = status_result, values = {
		banned = ban ~= nil,
		["until"] = tostring(until_ or ""),
		reason = ban and ban.reason or "",
		by = ban and ban.by or nil,
	} } };
end);

-- Every room on the MUC host, hidden ones too, one JSON object per line.
local json = require "util.json";

local rooms_result = dataforms_new {
	title = "All rooms";
	{ name = "FORM_TYPE", type = "hidden", value = NS .. "list-rooms" };
	{ name = "rooms", type = "text-multi" };
};

local function each_room()
	local muc = prosody.hosts[muc_host] and prosody.hosts[muc_host].modules.muc;
	if not muc then return nil; end
	return (muc.all_rooms or muc.each_room)();
end

local function list_rooms_handler(_, data)
	local rooms = each_room();
	if not rooms then
		return { status = "completed",
			error = { message = "No rooms service at " .. muc_host .. " (set otrv4plus_muc_host)." } };
	end
	local lines = {};
	for room in rooms do
		local occupants = 0;
		for _ in room:each_occupant() do occupants = occupants + 1; end
		lines[#lines + 1] = json.encode({
			jid = room.jid,
			name = room:get_name() or "",
			description = room:get_description() or "",
			password = room:get_password() ~= nil,
			hidden = room:get_hidden() and true or false,
			occupants = occupants,
		});
		if #lines >= 1000 then break; end
	end
	return { status = "completed", result = { layout = rooms_result,
		values = { rooms = table.concat(lines, "\n") } } };
end

-- Destroy any room on the rooms service. Owner (2026-10-18): signed in as
-- the server admin, Delete was refused on every room the admin had not
-- created -- XEP-0045 10.9 lets only a room's owner destroy it, and this
-- server does not count its admins as owners of the rooms service's rooms
-- (get_affiliation(admin) = nil). This command is the admin's own route,
-- offered to admins only, as the others above.
local destroy_form = dataforms_new {
	title = "Destroy a room";
	{ name = "FORM_TYPE", type = "hidden", value = NS .. "destroy-room" };
	{ name = "roomjid", type = "jid-single", required = true, label = "Room" };
	{ name = "reason", type = "text-single", label = "Reason (shown to occupants)" };
};

local destroy_handler = adhoc_simple(destroy_form, function (fields, err, data)
	if err then
		return { status = "completed", error = { message = "The form was not filled in." } };
	end
	local want = jid.prep(fields.roomjid or "");
	want = want and jid.bare(want);
	local _, h = jid.split(want or "");
	if not want or h ~= muc_host then
		return { status = "completed",
			error = { message = "Only rooms on " .. muc_host .. " can be destroyed here." } };
	end
	local rooms = each_room();
	if not rooms then
		return { status = "completed",
			error = { message = "No rooms service at " .. muc_host .. " (set otrv4plus_muc_host)." } };
	end
	for room in rooms do
		if room.jid == want then
			room:destroy(nil, (fields.reason or ""):sub(1, 200));
			module:log("warn", "%s destroyed the room %s", jid.bare(data.from), want);
			return { status = "completed", info = "Destroyed " .. want .. "." };
		end
	end
	return { status = "completed", error = { message = "There is no such room." } };
end);

module:provides("adhoc", adhoc_new("Destroy a room", NS .. "destroy-room", destroy_handler, "admin"));
module:provides("adhoc", adhoc_new("Ban an account", NS .. "ban-user", ban_handler, "admin"));
module:provides("adhoc", adhoc_new("Lift a ban", NS .. "unban-user", unban_handler, "admin"));
module:provides("adhoc", adhoc_new("Ban status", NS .. "ban-status", status_handler, "admin"));
module:provides("adhoc", adhoc_new("List all rooms", NS .. "list-rooms", list_rooms_handler, "admin"));
