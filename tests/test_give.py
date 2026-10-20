"""vault.give: lands in the receiver's vault with the giver's name; never the giver's own vault."""
import asyncio, sys
sys.path.insert(0, "/app")
import app.auth as auth, app.main as m


def demo():
    saved = (m._create_item_tool.run, auth.caller_has_write, auth.caller_bw_creds, m.audit.log_call)
    try:
        _checks()
    finally:
        m._create_item_tool.run, auth.caller_has_write, auth.caller_bw_creds, m.audit.log_call = saved
        auth._current_caller.set(None)
    print("vault.give checks OK")


def _checks():
    seen = {}

    async def fake_run(**kw):
        seen.update(kw)
        return "item-1"

    m._create_item_tool.run = fake_run
    auth.caller_has_write = lambda c: c == "mike"
    auth.caller_bw_creds = lambda c: {"k": c} if c in ("mike", "agent_c") else None
    m.audit.log_call = lambda **kw: seen.setdefault("audit", kw)
    tok = auth._current_caller.set("mike")
    give = getattr(m.vault_give, "fn", m.vault_give)
    assert asyncio.run(give(to="agent_c", name="Stripe", password="x")) == "item-1"
    assert seen["caller"] == "agent_c" and seen["creds"] == {"k": "agent_c"} and seen["name"] == "Stripe (from mike)"
    assert seen["audit"]["target_caller"] == "agent_c" and seen["audit"]["action"] == "give"
    for bad in ("mike", "nobody"):
        try:
            asyncio.run(give(to=bad, name="x", password="x")); raise AssertionError(bad)
        except ValueError:
            pass
    auth._current_caller.reset(tok)
    auth._current_caller.set("reader")
    try:
        asyncio.run(give(to="agent_c", name="x", password="x")); raise AssertionError("no write_ok")
    except PermissionError:
        pass


if __name__ == "__main__":
    demo()


def test_give():
    demo()
