-- SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
-- Copyright (C) 2025-2026 muc111
-- Minimal Prosody stubs for mod_otrv4plus_moderation.
local hooks, provided, store, logs = {}, {}, {}, {}
local closed = {}
local function split(j) local n,h = j:match("^([^@]+)@([^/]+)"); return n,h end
package.preload["util.jid"] = function() return {
  prep=function(j) if j:find(" ") then return nil end return j:lower() end,
  split=split, bare=function(j) return (j:gsub("/.*$","")) end } end
package.preload["core.usermanager"] = function() return {
  is_admin=function(j) return j=="alice@x.i2p" end,
  user_exists=function(n) return n=="bob" or n=="alice" end } end
package.preload["util.dataforms"] = function() return { new=function(t) return t end } end
package.preload["util.adhoc"] = function() return { new_simple_form=function(form, h) return h end } end
package.preload["util.json"] = function() return { encode=function(t) return "{"..t.jid.."}" end } end
local bobsess = { close=function(self, e) closed[#closed+1]=e end, username="bob" }
prosody = { hosts = { ["x.i2p"] = { sessions = { bob = { sessions = { r1 = bobsess } } } } } }
module = {
  host="x.i2p",
  open_store=function() return { get=function(_,k) return store[k] end, set=function(_,k,v) store[k]=v end } end,
  get_option_string=function(_,_,d) return d end,
  depends=function() end,
  require=function() return { new=function(name,node,h,perm) return {name=name,node=node,handler=h,perm=perm} end } end,
  hook=function(_,name,fn,prio) hooks[name]=fn end,
  log=function(_,lvl,...) logs[#logs+1]=lvl end,
  provides=function(_,kind,item) provided[item.node:match("#(.*)$")]=item end,
}
local f = assert(loadfile(arg_path))
f()
local function run(cmd, fields, from) return provided[cmd].handler(fields, nil, {from=from or "alice@x.i2p/phone"}) end
local out = {}
local function check(name, cond) out[#out+1] = (cond and "ok " or "FAIL ")..name end
for k,v in pairs(provided) do check("perm "..k, v.perm=="admin") end
local r = run("ban-user", {accountjid="bob@x.i2p", days="7", reason="spam"})
check("ban ok: "..tostring(r.info), r.info and r.info:find("Banned bob@x.i2p until") and r.info:find("signed out"))
check("session closed policy-violation", closed[1] and closed[1].condition=="policy-violation" and closed[1].text:find("until=%d+"))
local ev = { session = { username="bob", close=function(self,e) closed[#closed+1]=e end } }
check("bind refused", hooks["pre-resource-bind"](ev) == false and ev.error.condition=="policy-violation")
local okev = { session = { username="carol", close=function() end } }
check("others pass", hooks["pre-resource-bind"](okev) == nil)
local s = run("ban-status", {accountjid="bob@x.i2p"})
check("status banned", s.result.values.banned == true and tonumber(s.result.values["until"]) > os.time())
check("self ban refused", run("ban-user", {accountjid="alice@x.i2p", days="0"}).error ~= nil)
check("other host refused", run("ban-user", {accountjid="bob@y.i2p", days="0"}).error ~= nil)
check("bad days refused", run("ban-user", {accountjid="bob@x.i2p", days="-1"}).error ~= nil)
check("no such account", run("ban-user", {accountjid="zed@x.i2p", days="1"}).error ~= nil)
check("unban", run("unban-user", {accountjid="bob@x.i2p"}).info:find("lifted"))
check("bind allowed after unban", hooks["pre-resource-bind"](ev) == nil)
run("ban-user", {accountjid="bob@x.i2p", days="0"})
check("perm text", closed[#closed].text:find("permanently %(until=0%)"))
store.bob["until"] = os.time() - 5
check("expired ban lifts itself", hooks["pre-resource-bind"](ev) == nil and store.bob == nil)
check("list-rooms without muc errors", provided["list-rooms"].handler(nil, {}).error ~= nil)
check("destroy without muc errors", run("destroy-room", {roomjid="lol@conference.x.i2p"}).error ~= nil)
local destroyed = {}
local function room(j) return { jid = j, destroy = function(self, _, why) destroyed[#destroyed+1] = self.jid .. "|" .. why end } end
prosody.hosts["conference.x.i2p"] = { modules = { muc = { each_room = function()
	local list, i = { room("lol@conference.x.i2p"), room("team@conference.x.i2p") }, 0
	return function() i = i + 1; return list[i] end
end } } }
check("perm destroy-room", provided["destroy-room"].perm == "admin")
local d = run("destroy-room", {roomjid="lol@conference.x.i2p", reason="clean up"})
check("destroy-room destroys exactly that room", d.info and destroyed[1] == "lol@conference.x.i2p|clean up" and #destroyed == 1)
check("destroy-room: another host refused", run("destroy-room", {roomjid="lol@elsewhere.i2p"}).error ~= nil and #destroyed == 1)
check("destroy-room: unknown room said", run("destroy-room", {roomjid="nope@conference.x.i2p"}).error.message == "There is no such room.")
return table.concat(out, "\n")
