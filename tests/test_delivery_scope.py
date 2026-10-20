"""Synthetic delivery isolation regression. Never accesses a real vault."""
import asyncio,json,unittest
from unittest.mock import AsyncMock,patch
from app import provision,bw_client
from app.tools import update_field,create_item

class Delivery(unittest.TestCase):
 def test_same_name_never_updates_peer(self):
  request=AsyncMock();request.headers={'X-Admin-Key':'fixture-admin'};request.json.return_value={'bot_name':'lux','name':'example Panel — Qoopia','password':'fixture-password'}
  peers=[{'id':'peer','name':'example Panel — Qoopia','collectionIds':['peer-col']},{'id':'own','name':'example Panel — Qoopia','collectionIds':['own-col']}]
  with patch.object(provision,'ADMIN_KEY','fixture-admin'),patch.object(provision.auth,'caller_bw_creds',return_value={'fixture':True}),patch.object(bw_client,'list_collections',AsyncMock(return_value=[{'name':'lux','id':'own-col','organizationId':'org'}])),patch.object(bw_client,'list_ciphers',AsyncMock(return_value=peers)),patch.object(update_field,'run',AsyncMock()) as update,patch.object(create_item,'run',AsyncMock(return_value='new')) as create:
   response=asyncio.run(provision.deliver_endpoint(request));self.assertEqual(response.status_code,200);self.assertEqual(update.call_args.kwargs['item_id'],'own');create.assert_not_called()
   peers.pop();update.reset_mock()
   response=asyncio.run(provision.deliver_endpoint(request));self.assertEqual(response.status_code,200);update.assert_not_called();self.assertEqual(create.call_args.kwargs['collection_id'],'own-col')
if __name__=='__main__':unittest.main()
