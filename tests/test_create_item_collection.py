"""Payload shape for create_item: a collection needs its organization.

Vaultwarden silently files a cipher in the personal vault when collectionIds is
set without organizationId, so the collection link is lost with no error. This
pins that pairing.
"""
import sys

sys.path.insert(0, "/app")

from app.tools.create_item import _build_login_payload  # noqa: E402


def demo():
    both = _build_login_payload(
        name="x", username="u", password="p", url=None, notes=None,
        collection_id="col-1", organization_id="org-1", custom_fields=None)
    assert both["collectionIds"] == ["col-1"]
    assert both["organizationId"] == "org-1"

    # No collection: never claim an organization.
    personal = _build_login_payload(
        name="x", username=None, password=None, url=None, notes=None,
        collection_id=None, organization_id="org-1", custom_fields=None)
    assert personal["collectionIds"] == []
    assert "organizationId" not in personal

    # The regression itself: collection without org must not pretend it worked.
    orphan = _build_login_payload(
        name="x", username=None, password=None, url=None, notes=None,
        collection_id="col-1", organization_id=None, custom_fields=None)
    assert orphan["collectionIds"] == ["col-1"]
    assert "organizationId" not in orphan

    from app.tools.create_item import _pick_collection
    cols = [{"id": "s", "name": "shared", "organizationId": "o"}, {"id": "m", "name": "mike", "organizationId": "o"}]
    assert _pick_collection(cols, "mike", None)["id"] == "m"
    assert _pick_collection(cols, "other-name", None)["id"] == "m"  # sole own folder
    assert _pick_collection(cols, "mike", "shared")["id"] == "s"
    assert _pick_collection([cols[0]], "mike", None) is None  # never default into shared
    try:
        _pick_collection(cols, "mike", "nope"); raise AssertionError("must refuse")
    except ValueError:
        pass
    print("create_item payload checks OK")


if __name__ == "__main__":
    demo()
