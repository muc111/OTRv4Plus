#!/usr/bin/env python3
"""The registry in `security_invariants.py` must describe reality.

An invariant with no enforcing test is a comment.  A named test module that
does not exist is worse -- VERSIONING.md claimed the SMP wire byte was pinned
by `test_protocol_version.py` for a whole release before it actually was, and
nothing noticed because prose cannot be executed.

This file is what makes the registry load-bearing.
"""

import os
import sys

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TESTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, TESTS)
sys.path.insert(0, ROOT)

import security_invariants as S


class TestTheRegistryIsWellFormed:

    def test_there_are_invariants(self):
        assert len(S.INVARIANTS) >= 16

    def test_ids_are_unique_and_ordered(self):
        ids = [i.id for i in S.INVARIANTS]
        assert len(set(ids)) == len(ids)
        assert ids == sorted(ids)

    def test_ids_follow_the_scheme(self):
        import re
        for inv in S.INVARIANTS:
            assert re.fullmatch(r"INV-\d{2}", inv.id), inv.id

    def test_every_invariant_states_something(self):
        for inv in S.INVARIANTS:
            assert inv.statement.strip()
            assert inv.statement.rstrip().endswith("."), (
                "%s is not a sentence" % inv.id)

    def test_statuses_are_from_the_known_set(self):
        for inv in S.INVARIANTS:
            assert inv.status in S.ENFORCED_STATUSES, (
                "%s has status %r" % (inv.id, inv.status))

    def test_partial_and_accepted_state_their_limits(self):
        """The whole point of those statuses is to record what is NOT
        covered.  One without a limit is an ENFORCED claim in disguise."""
        for inv in S.INVARIANTS:
            if inv.status in ("PARTIAL", "ACCEPTED"):
                assert inv.limits.strip(), (
                    "%s is %s but names no limitation" % (inv.id, inv.status))

    def test_enforced_invariants_do_not_claim_limits(self):
        for inv in S.INVARIANTS:
            if inv.status == "ENFORCED":
                assert not inv.limits.strip(), (
                    "%s is ENFORCED but records a limitation, so it is "
                    "really PARTIAL" % inv.id)


class TestEveryInvariantHasATest:

    def test_each_names_at_least_one_module(self):
        for inv in S.INVARIANTS:
            assert inv.tests, "%s has no enforcing test" % inv.id

    @pytest.mark.parametrize("module", S.all_test_modules())
    def test_the_named_module_exists(self, module):
        assert os.path.exists(os.path.join(TESTS, module)), (
            "%s is named by the registry but does not exist" % module)

    @pytest.mark.parametrize("module", S.all_test_modules())
    def test_the_named_module_contains_tests(self, module):
        src = open(os.path.join(TESTS, module), encoding="utf-8").read()
        assert "def test_" in src, "%s contains no tests" % module

    @pytest.mark.parametrize("module", S.all_test_modules())
    def test_the_named_module_says_which_invariant_it_enforces(self, module):
        """A reader arriving at the test should not have to guess."""
        src = open(os.path.join(TESTS, module), encoding="utf-8").read()
        head = src[:2000]
        owners = [i.id for i in S.INVARIANTS if module in i.tests]
        assert any(owner in head for owner in owners), (
            "%s enforces %s but does not name it near the top"
            % (module, "/".join(owners)))


class TestLookup:

    def test_by_id_finds_them(self):
        assert S.by_id("INV-01").id == "INV-01"

    def test_by_id_raises_for_an_unknown_id(self):
        with pytest.raises(KeyError):
            S.by_id("INV-99")

    def test_all_test_modules_is_deduplicated(self):
        mods = S.all_test_modules()
        assert len(set(mods)) == len(mods)


class TestTheDocumentAgrees:
    """SECURITY_INVARIANTS.md is generated from this registry by hand.
    If they disagree, the prose is the one that is wrong -- but a reader will
    believe the prose, so they must not disagree."""

    def _doc(self):
        path = os.path.join(ROOT, "SECURITY_INVARIANTS.md")
        if not os.path.exists(path):
            pytest.skip("SECURITY_INVARIANTS.md not written yet")
        return open(path, encoding="utf-8").read()

    def test_every_invariant_appears(self):
        doc = self._doc()
        for inv in S.INVARIANTS:
            assert inv.id in doc, "%s is missing from the document" % inv.id

    def test_no_invented_invariants(self):
        import re
        doc = self._doc()
        known = {i.id for i in S.INVARIANTS}
        for found in set(re.findall(r"INV-\d{2}", doc)):
            assert found in known, (
                "%s is documented but is not in the registry" % found)

    def test_the_document_names_the_enforcing_tests(self):
        doc = self._doc()
        for module in S.all_test_modules():
            assert module in doc, (
                "%s enforces an invariant but the document does not say so"
                % module)
