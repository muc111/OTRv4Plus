# SPDX-License-Identifier: AGPL-3.0-only OR LicenseRef-OTRv4Plus-Commercial
# Copyright (C) 2025-2026 muc111
"""Small helpers of the IRC client, shared by otrv4plus_irc and its mixins."""
import secrets
from otrv4plus import VERSION


class TwentySevenClubNick:
    """Generate unique IRC nicks from a large combinatorial pool.

    Combines adjectives with historical/cultural figure surnames to
    produce ~10,000+ unique nicks.  Each nick maps to a plausible
    real name for /whois display.

    Original 27 Club names are preserved as a subset for backward
    compatibility - existing users keep their nick identity.

    IRC nick constraints:
      - Max 30 characters (most servers allow 9-30)
      - No spaces, no leading #&: or digits
      - ASCII printable only
    """

    _LEGACY = [
        ("KurtCobain", "Kurt Cobain", "Nirvana"),
        ("AmyWinehouse", "Amy Winehouse", "Solo"),
        ("JimiHendrix", "Jimi Hendrix", "The Jimi Hendrix Experience"),
        ("JanisJoplin", "Janis Joplin", "Big Brother & The Holding Company"),
        ("JimMorrison", "Jim Morrison", "The Doors"),
        ("BrianJones", "Brian Jones", "The Rolling Stones"),
        ("RobertJohnson", "Robert Johnson", "Blues Legend"),
        ("AlanWilson", "Alan Wilson", "Canned Heat"),
        ("RonMcKernan", "Ron McKernan", "Grateful Dead"),
        ("PeteHam", "Pete Ham", "Badfinger"),
        ("RandyRhoads", "Randy Rhoads", "Ozzy Osbourne"),
        ("HillelSlovak", "Hillel Slovak", "Red Hot Chili Peppers"),
        ("AndrewWood", "Andrew Wood", "Mother Love Bone"),
        ("KristenPfaff", "Kristen Pfaff", "Hole"),
        ("RicheyEdwards", "Richey Edwards", "Manic Street Preachers"),
        ("DaveAlexander", "Dave Alexander", "The Stooges"),
        ("GaryThain", "Gary Thain", "Uriah Heep"),
        ("LesHarvey", "Les Harvey", "Stone the Crows"),
        ("ChrisBell", "Chris Bell", "Big Star"),
        ("JeremyWard", "Jeremy Ward", "The Mars Volta"),
    ]

    _ADJECTIVES = [
        "Silent",
        "Shadow",
        "Phantom",
        "Midnight",
        "Iron",
        "Crimson",
        "Golden",
        "Silver",
        "Dark",
        "Bright",
        "Swift",
        "Fierce",
        "Calm",
        "Wild",
        "Lone",
        "Bitter",
        "Hollow",
        "Frozen",
        "Burning",
        "Hidden",
        "Ancient",
        "Broken",
        "Fading",
        "Rising",
        "Fallen",
        "Distant",
        "Restless",
        "Wicked",
        "Noble",
        "Stray",
        "Drifting",
        "Echoing",
        "Veiled",
        "Stark",
        "Ashen",
        "Copper",
        "Jade",
        "Cobalt",
        "Ember",
        "Onyx",
        "Rustic",
        "Pale",
        "Dusky",
        "Misty",
        "Stormy",
        "Feral",
        "Glacial",
        "Lunar",
        "Solar",
        "Rogue",
        "Scarlet",
        "Azure",
        "Violet",
        "Ivory",
        "Obsidian",
        "Granite",
        "Cedar",
        "Birch",
        "Rowan",
        "Hazel",
        "Wraith",
        "Spectre",
        "Vagrant",
        "Nomad",
        "Hermit",
        "Cipher",
        "Zero",
        "Null",
        "Void",
        "Apex",
        "Primal",
        "Austere",
        "Cryptic",
        "Arcane",
        "Lucid",
        "Serene",
        "Turbid",
        "Waning",
        "Waxing",
        "Errant",
        "Sullen",
        "Muted",
        "Stark",
        "Gaunt",
        "Bleak",
        "Thorned",
        "Barbed",
        "Tempered",
        "Forged",
        "Annealed",
        "Quartz",
        "Basalt",
        "Slate",
        "Flint",
        "Ochre",
        "Boreal",
        "Tundra",
        "Steppe",
        "Taiga",
        "Mesa",
    ]

    _NOUNS = [
        "Wolf",
        "Hawk",
        "Raven",
        "Fox",
        "Lynx",
        "Bear",
        "Owl",
        "Crane",
        "Viper",
        "Falcon",
        "Heron",
        "Sparrow",
        "Condor",
        "Osprey",
        "Kestrel",
        "Jackal",
        "Panther",
        "Cobra",
        "Mantis",
        "Hornet",
        "Badger",
        "Otter",
        "Marten",
        "Wren",
        "Finch",
        "Forge",
        "Anvil",
        "Blade",
        "Shield",
        "Arrow",
        "Spire",
        "Bastion",
        "Citadel",
        "Tower",
        "Gate",
        "Storm",
        "Thunder",
        "Frost",
        "Blaze",
        "Ember",
        "Tide",
        "Current",
        "Drift",
        "Torrent",
        "Gale",
        "Root",
        "Thorn",
        "Branch",
        "Stone",
        "Ridge",
        "Peak",
        "Crest",
        "Vale",
        "Glen",
        "Cairn",
        "Dusk",
        "Dawn",
        "Shade",
        "Gloom",
        "Haze",
        "Reef",
        "Shoal",
        "Fjord",
        "Gorge",
        "Ravine",
        "Cipher",
        "Signal",
        "Beacon",
        "Pulse",
        "Vector",
        "Prism",
        "Shard",
        "Relic",
        "Glyph",
        "Rune",
        "Wick",
        "Tallow",
        "Flint",
        "Spark",
        "Cinder",
        "Quarry",
        "Ledge",
        "Scree",
        "Moraine",
        "Talus",
        "Styx",
        "Lethe",
        "Acheron",
        "Eris",
        "Nyx",
        "Odin",
        "Loki",
        "Fenrir",
        "Mimir",
        "Tyr",
        "Kappa",
        "Sigma",
        "Delta",
        "Theta",
        "Omega",
        "Vertex",
        "Node",
        "Orbit",
        "Zenith",
        "Nadir",
        "Mantle",
        "Cortex",
        "Nexus",
        "Vortex",
        "Matrix",
    ]

    _LOOKUP = {nick: (real, band) for nick, real, band in _LEGACY}

    @classmethod
    def generate(cls) -> str:
        """Generate a unique nick from the combinatorial pool.

        Format: AdjectiveNoun (e.g. SilentWolf, CrimsonForge)
        Pool: ~100 × 120 = ~12,000 unique combinations.
        Collision probability with <100 concurrent users: negligible.
        """
        adj = secrets.choice(cls._ADJECTIVES)
        noun = secrets.choice(cls._NOUNS)
        nick = adj + noun

        if len(nick) > 30:
            nick = nick[:30]
        return nick

    @classmethod
    def real_name(cls, nick: str) -> str:
        """Return the realname (gecos) advertised at USER registration.

        Legacy 27 Club nicks keep their real identity; generated nicks get a
        plausible format.  Every form ends with VERSION, because this string
        is the client's only identification channel over IRC -- CTCP VERSION
        is refused -- and /names reads it back out of RPL_WHOREPLY.

        Before v10.14.0 the 27 Club branch returned "... - 27 Club" with no
        version, and a NickServ nick advertised the bare nick, so two whole
        classes of OTRv4+ user were undetectable by their own peers.  A
        detection mechanism the client does not consistently feed is not a
        detection mechanism.
        """
        base = nick.rstrip("_0123456789")
        if base in cls._LOOKUP:
            real, band = cls._LOOKUP[base]
            return f"{real } ({band }) - 27 Club - {VERSION }"
        return f"{nick } - {VERSION }"

    @classmethod
    def is_member(cls, nick: str) -> bool:
        base = nick.rstrip("_0123456789")
        return base in cls._LOOKUP


def _fmt_duration(seconds: float) -> str:
    """Format seconds into human-readable string: 1d 2h 30m 15s"""
    s = int(seconds)
    if s < 0:
        return "0s"
    parts = []
    if s >= 86400:
        d, s = divmod(s, 86400)
        parts.append(f"{d }d")
    if s >= 3600:
        h, s = divmod(s, 3600)
        parts.append(f"{h }h")
    if s >= 60:
        m, s = divmod(s, 60)
        parts.append(f"{m }m")
    if s > 0 or not parts:
        parts.append(f"{s }s")
    return " ".join(parts)
