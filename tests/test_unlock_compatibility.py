from unittest.mock import AsyncMock
import pytest
from app import bw_client

CREDS = {'bw_clientid':'test-id','bw_clientsecret':'test-api-secret','bw_password':'test-master'}

@pytest.mark.asyncio
async def test_unsupported_key_id_backfill_retries_only_native_unlock(monkeypatch,tmp_path):
    calls=[]
    results=[(0,b'',b''),(0,b'',b''),(1,b'',b'KeyIdBackfillError: Api HTTP 404'),(0,b'test-session',b'')]
    async def spawn(*args,**kwargs):
        calls.append((args,kwargs))
        rc,out,err=results.pop(0)
        class Child:
            returncode=rc
            async def communicate(self,input=None):return out,err
        return Child()
    monkeypatch.setattr(bw_client.asyncio,'create_subprocess_exec',spawn)
    assert await bw_client._login_and_unlock(CREDS,str(tmp_path))=='test-session'
    assert [c[0][1] for c in calls]==['config','login','unlock','unlock']
    assert all(CREDS['bw_password'] not in c[0] for c in calls)
    assert calls[-1][1]['env']['BW_PASSWORD']==CREDS['bw_password']

@pytest.mark.asyncio
@pytest.mark.parametrize('message',[b'Invalid master password',b'HTTP 429',b'HTTP 404',b'KeyIdBackfillError: Local NoKeyId'])
async def test_other_unlock_failures_are_not_retried(monkeypatch,tmp_path,message):
    calls=[]
    async def spawn(*args,**kwargs):
        calls.append(args)
        class Child:
            returncode=1 if args[1]=='unlock' else 0
            async def communicate(self,input=None):return b'',message if self.returncode else b''
        return Child()
    monkeypatch.setattr(bw_client.asyncio,'create_subprocess_exec',spawn)
    with pytest.raises(RuntimeError):await bw_client._login_and_unlock(CREDS,str(tmp_path))
    assert [c[1] for c in calls]==['config','login','unlock']
