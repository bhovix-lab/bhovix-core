"""Anchor suite (slice 2 P3b) over every registered anchor kind: what the chain relies on."""

import inspect

import pytest

from hadavin_sdk.audit.anchors import AnchorConflict
from tests.contracts.kinds import KINDS


@pytest.fixture(params=sorted(KINDS["anchor"]))
def anchor(request, tmp_path):
    made = KINDS["anchor"][request.param](tmp_path)
    if not inspect.isgenerator(made):
        return made
    value = next(made)
    request.addfinalizer(lambda: next(made, None))
    return value


def test_puts_read_back_and_a_lost_answer_retry_is_anchored(anchor):
    anchor.put(3, "a" * 64, "b" * 128)
    anchor.put(6, "c" * 64, "d" * 128)
    anchor.put(3, "a" * 64, "b" * 128)  # the same bytes again: an earlier put whose answer was lost
    assert anchor.all() == {3: ("a" * 64, "b" * 128), 6: ("c" * 64, "d" * 128)}


def test_an_anchor_is_never_replaced(anchor):
    anchor.put(9, "a" * 64, "b" * 128)
    with pytest.raises(AnchorConflict):
        anchor.put(9, "f" * 64, "e" * 128)
    assert anchor.all()[9] == ("a" * 64, "b" * 128)
