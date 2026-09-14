"""SPEC.md is a normative document; it must agree with the implementation.

WHY THIS EXISTS
---------------
SPEC.md opens by claiming it is "precise enough that an independent
implementation can be written from this document alone, without reference to
the source code." That is a strong claim and it is the one a peer reviewer
will test. It had drifted:

  * the version header said 10.14.0 while the code was at 10.30.0;
  * the canonical usage-ID registry in §2.2 omitted FILE_TRANSFER_WRAP (0x22),
    which §9A nonetheless used;
  * there was no TLV registry at all -- the document mentioned TLVs once, in
    passing, while the wire format has ten types;
  * TLV 0x0020 (TIP) and the `?OTRv4-TRADE:` body prefix appeared nowhere.

Prose drifts silently because nothing executes it. These tests execute the
parts that are checkable: every constant the document states as normative is
compared against the constant the code actually uses.

WHAT THIS DELIBERATELY DOES NOT CHECK
-------------------------------------
Whether the protocol is *correct*, or whether the prose describes the
algorithm it claims to. No test can do that; that is what the peer review is
for. This only ensures the reviewer is reading numbers that match the code, so
their time goes on the design rather than on chasing stale constants.
"""

import re

import pytest

SPEC = "SPEC.md"


def spec_text():
    return open(SPEC).read()


def _section(text, start, end):
    return text[text.index(start):text.index(end)]


# ---------------------------------------------------------------------------
# the version stamp
# ---------------------------------------------------------------------------

class TestTheVersionStamp:

    def test_it_matches_the_engine(self):
        """A spec stamped with an old version is assumed stale, correctly.

        The reviewer's first question about a 10.14.0 document describing a
        10.30.0 implementation is which parts are which, and there is no
        answer to give them.
        """
        engine = re.search(r'^VERSION = "OTRv4\+ ([\d.]+)"',
                           open("otrv4+.py").read(), re.M)
        assert engine, "VERSION is no longer a module-level literal in otrv4+.py"
        stamped = re.search(r'^\*\*Version:\*\* ([\d.]+)', spec_text(), re.M)
        assert stamped, "SPEC.md has no version header"
        assert stamped.group(1) == engine.group(1), (
            "SPEC.md is stamped %s but the engine is %s"
            % (stamped.group(1), engine.group(1)))


# ---------------------------------------------------------------------------
# §2.2 KDF usage IDs
# ---------------------------------------------------------------------------

def code_usage_ids():
    src = open("Rust/src/kdf.rs").read()
    block = src[src.index("pub mod usage"):]
    block = block[:block.index("\n}")]
    return {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r'pub const (\w+):\s*u8 = (0x[0-9a-fA-F]+);',
                                 block)}


def spec_usage_ids():
    table = _section(spec_text(), "### 2.2 Usage IDs", "### 2.3")
    return {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r'\|\s*(\w+)\s*\|\s*(0x[0-9a-fA-F]+)\s*\|',
                                 table)}


class TestTheUsageIdRegistry:

    def test_every_usage_id_in_the_code_is_documented(self):
        missing = sorted(set(code_usage_ids()) - set(spec_usage_ids()))
        assert missing == [], (
            "these usage IDs exist in Rust/src/kdf.rs but not in SPEC §2.2, "
            "which is the registry an independent implementer would work "
            "from: %s" % missing)

    def test_no_documented_usage_id_is_invented(self):
        extra = sorted(set(spec_usage_ids()) - set(code_usage_ids()))
        assert extra == [], (
            "SPEC §2.2 documents usage IDs nothing implements: %s" % extra)

    def test_the_values_agree(self):
        code, doc = code_usage_ids(), spec_usage_ids()
        bad = {k: (hex(code[k]), hex(doc[k]))
               for k in code if k in doc and code[k] != doc[k]}
        assert bad == {}, "usage ID value mismatch (code, spec): %s" % bad

    def test_the_domain_separator_is_what_the_spec_says(self):
        """The spec is explicit that it is "OTRv4", not "OTRv4+"."""
        assert 'b"OTRv4"' in open("Rust/src/kdf.rs").read()
        assert '`"OTRv4"` is the 5-byte ASCII domain separator' in spec_text()


# ---------------------------------------------------------------------------
# §5.6 TLV registry
# ---------------------------------------------------------------------------

def code_tlv_types():
    """The table actually used on the wire.

    otrv4+.py carries a second, older table (OTRv4Constants.TLV_TYPE_*) which
    has no call sites and which disagrees -- it allocates 0x08. OTRv4TLV is the
    one the engine constructs and dispatches on, so it is the one the spec must
    match.
    """
    src = open("otrv4+.py").read()
    block = src[src.index("class OTRv4TLV:"):]
    block = block[:block.index("SMP_TYPES")]
    return {m.group(1): int(m.group(2), 16)
            for m in re.finditer(r'^    ([A-Z][A-Z0-9_]*)\s*=\s*(0x[0-9a-fA-F]+)',
                                 block, re.M)}


def spec_tlv_types():
    table = _section(spec_text(), "### 5.6 TLV Records", "#### 5.6.1")
    return {m.group(2): int(m.group(1), 16)
            for m in re.finditer(r'\|\s*(0x[0-9a-fA-F]{4})\s*\|\s*(\w+)\s*\|',
                                 table)}


class TestTheTlvRegistry:

    def test_the_spec_has_one_at_all(self):
        """The gap this file was written for.

        The document claimed to be implementable standalone while never
        listing the TLV types that make up a message body.
        """
        assert "### 5.6 TLV Records" in spec_text()
        assert len(spec_tlv_types()) >= 9

    def test_every_wire_tlv_is_documented(self):
        missing = sorted(set(code_tlv_types()) - set(spec_tlv_types()))
        assert missing == [], (
            "these TLV types are constructed by the engine but absent from "
            "SPEC §5.6: %s" % missing)

    def test_the_values_agree(self):
        code, doc = code_tlv_types(), spec_tlv_types()
        bad = {k: (hex(code[k]), hex(doc[k]))
               for k in code if k in doc and code[k] != doc[k]}
        assert bad == {}, "TLV value mismatch (code, spec): %s" % bad

    def test_the_unallocated_type_is_called_out(self):
        """0x0008 is the trap: OTRv4 allocates it, OTRv4+ does not.

        An implementer working from OTRv4 would reasonably send a
        client-profile TLV. The spec has to say that this protocol will not
        understand it.
        """
        assert "CLIENT_PROFILE" not in code_tlv_types()
        assert "`0x0008` is **not allocated**" in spec_text()

    def test_the_extension_range_is_stated(self):
        """Without it, the next extension collides with a future OTRv4 type."""
        assert "OTRv4+ extension types begin at `0x0020`" in spec_text()


class TestTheApplicationLayerExtensions:

    def test_the_tip_tlv_bounds_match_the_implementation(self):
        import importlib.util
        spec_mod = importlib.util.spec_from_file_location(
            "tipmod", "otrv4plus_tip.py")
        # Read the constants without importing: the module pulls in the engine.
        src = open("otrv4plus_tip.py").read()
        bounds = {m.group(1): int(m.group(2))
                  for m in re.finditer(r'^(MAX_\w+)\s*=\s*(\d+)', src, re.M)}
        text = spec_text()
        for name, value in bounds.items():
            assert str(value) in text, (
                "%s = %d is enforced by otrv4plus_tip.py but the figure does "
                "not appear in SPEC §5.6.2" % (name, value))

    def test_the_tip_tlv_type_agrees_with_the_engine(self):
        src = open("otrv4plus_tip.py").read()
        mirrored = int(re.search(r'TIP_TLV_TYPE = (0x[0-9a-fA-F]+)',
                                 src).group(1), 16)
        assert code_tlv_types()["TIP"] == mirrored
        assert spec_tlv_types()["TIP"] == mirrored

    def test_the_trade_prefix_is_documented(self):
        prefix = re.search(r'TRADE_PREFIX = "([^"]+)"',
                           open("otrv4plus_trade.py").read()).group(1)
        assert prefix in spec_text(), (
            "%r appears on the wire inside encrypted bodies and is documented "
            "nowhere in SPEC.md" % prefix)


# ---------------------------------------------------------------------------
# §1 fixed sizes
# ---------------------------------------------------------------------------

class TestTheFixedSizes:

    def test_they_match_the_dake_constants(self):
        src = open("Rust/src/dake.rs").read()
        code = {m.group(1): int(m.group(2))
                for m in re.finditer(r'const (\w+):\s*usize = (\d+);', src)}
        table = _section(spec_text(), "### 1.1 Fixed Sizes",
                         "## 2. Key Derivation Function")
        expected = {
            "ED448_PUB_SIZE": "Ed448 public key",
            "X448_PUB_SIZE": "X448 public key",
            "MLKEM_EK_SIZE": "ML-KEM-1024 encapsulation key (ek)",
            "MLKEM_CT_SIZE": "ML-KEM-1024 ciphertext (ct)",
            "MLDSA_PUB_SIZE": "ML-DSA-87 public key",
            "MLDSA_SIG_SIZE": "ML-DSA-87 signature",
        }
        for const, label in expected.items():
            if const not in code:
                pytest.skip("%s is no longer a literal in dake.rs" % const)
            row = re.search(r'\|\s*%s\s*\|\s*(\d+)\s*\|'
                            % re.escape(label), table)
            assert row, "SPEC §1.1 has no row for %r" % label
            assert int(row.group(1)) == code[const], (
                "%s: spec says %s, dake.rs says %d"
                % (label, row.group(1), code[const]))


# ---------------------------------------------------------------------------
# §6 SMP
# ---------------------------------------------------------------------------

class TestTheSmpParameters:

    def _smp(self):
        return open("Rust/src/smp.rs").read()

    def test_the_wire_versions_agree(self):
        code = {m.group(1): int(m.group(2), 16) for m in re.finditer(
            r'const (SMP_VERSION_\w+):\s*u8 = (0x[0-9a-fA-F]+);', self._smp())}
        assert code == {"SMP_VERSION_CLASSICAL": 1,
                        "SMP_VERSION_PQ": 2,
                        "SMP_VERSION_PQ_ARGON2": 3}, code
        text = spec_text()
        assert "`0x01` = classical SMP only" in text
        assert "`0x03` = hybrid post-quantum, Argon2id" in text

    def test_the_argon2_costs_are_the_documented_ones(self):
        """These are wire format: differing costs make SMP fail as a mismatch."""
        src = self._smp()
        m = int(re.search(r'ARGON2_M_COST_KIB: u32 = ([\d_]+)',
                          src).group(1).replace("_", ""))
        t = int(re.search(r'ARGON2_T_COST:\s*u32 = (\d+)', src).group(1))
        p = int(re.search(r'ARGON2_P_COST:\s*u32 = (\d+)', src).group(1))
        assert (m, t, p) == (65536, 3, 4), (m, t, p)
        text = spec_text()
        assert "m        = 65536 KiB" in text
        assert "t        = 3" in text
        assert "p        = 4" in text

    def test_the_salt_domain_is_byte_for_byte(self):
        domain = re.search(r'ARGON2_SALT_DOMAIN: &\[u8\] = b"([^"]+)"',
                           self._smp()).group(1)
        literal = domain.replace(r"\x00", "")
        assert literal in spec_text()
        assert len(literal) == 24, (
            "the spec calls this a 24-byte literal; it is %d" % len(literal))
