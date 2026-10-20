import httpx
import pytest
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route
from app.middleware import BearerAuthMiddleware


@pytest.mark.asyncio
async def test_only_exact_capability_method_paths_bypass_bearer():
    async def endpoint(request):
        return JSONResponse({'ok': True})
    paths = ['/intake/', '/intake/session', '/intake/submit', '/intake/confirm', '/intake/status', '/intake/admin', '/intake/status/extra']
    app = Starlette(routes=[Route(path, endpoint, methods=['GET','POST','DELETE']) for path in paths])
    app.add_middleware(BearerAuthMiddleware)
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vault.example') as c:
        for path in paths:
            for method in ('GET', 'POST', 'DELETE'):
                r = await c.request(method, path)
                expected = (method, path) in BearerAuthMiddleware.INTAKE_PATHS
                assert r.status_code == (200 if expected else 401)


@pytest.mark.asyncio
async def test_real_app_registers_tools_and_capability_routes(tmp_path, monkeypatch):
    monkeypatch.setenv('INTAKE_PUBLIC_BASE_URL', 'https://vault.example')
    monkeypatch.setenv('INTAKE_STATE_DIR', str(tmp_path))
    from app import main
    app = main._build_asgi_app()
    tools = {t.name for t in await main.mcp.list_tools()}
    assert {'vault.intake_create', 'vault.intake_status'} <= tools
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url='https://vault.example') as c:
        assert (await c.get('/intake/')).status_code == 200
        assert (await c.post('/intake/session', json={'capability':'0'*64}, headers={'Origin':'https://vault.example'})).status_code == 403
        assert (await c.post('/mcp', json={})).status_code == 401
