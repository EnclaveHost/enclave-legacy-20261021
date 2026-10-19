import {test,expect} from '@playwright/test';
import {seedStorage} from '../fixtures/session.mjs';
const appId='0x'+'cd'.repeat(32);
async function seedCatalog(page){
 return page.evaluate(async appId=>{
  const m=await import('/js/core/catalog.js');
  const {emit}=await import('/js/core/util.js');
  const app={appId,publisher:'0x'+'12'.repeat(20),slug:'independent-app',name:'Independent app',description:'test',active:false,versionCount:3,
    versions:[{version:'1',cid:'bafktest1',approval:1,yanked:false},{version:'2',cid:'bafktest2',approval:2,yanked:true},{version:'3',cid:'bafktest3',approval:0,yanked:false}].map(v=>({...v,verified:false,ports:'http',memMb:64,cpuGflops:2,vramMb:0,gpuGflops:0,config:''}))};
  Object.assign(m.STORE,{apps:[app],byId:{[appId]:app},sel:{[appId]:1},loaded:true,loading:false,at:Date.now(),owner:'0x'+'34'.repeat(20)});
  emit('enclave:catalog',{type:'loaded'});
  const result=m.resolveAppRef('independent-app:2');
  return {result,visible:m.visibleVerIdxs(app),recommended:m.defaultIdx(app),missing:m.resolveAppRef('independent-app:missing')};
 },appId);
}
test('explicit catalog releases remain visible and deployable with host-local admission notices',async({page,context})=>{
 await seedStorage(context,page);
 await page.goto('/apps?app='+appId);
 await page.waitForSelector('#appDetailView',{state:'attached'}).catch(()=>{});
 const result=await seedCatalog(page);
 expect(result.visible).toEqual([0,1,2]);expect(result.recommended).toBe(0);
 expect(result.result.reference).toBe('catalog://'+appId+'/1');
 expect(result.result.error).toBeUndefined();expect(result.result.notice).toContain('delisted, yanked, rejected');expect(result.missing.error).toContain('no live version');
 const detail=page.locator('c-app-detail');
 await expect(detail).toContainText('Independent app');
 await expect(detail.locator('[data-act="deploy"]')).toBeEnabled();
 await expect(detail.locator('[data-act="reject"]')).toHaveCount(0);
 await detail.locator('[data-act="deploy"]').dispatchEvent('click');
 await expect(page.locator('#quickDeploy .qd-catalog')).toContainText('Each host decides');
 await expect(page.locator('#quickDeploy .qd-catalog')).toContainText('rejected');
});
test('All releases exposes delisted apps without changing the approved recommendation tab',async({page,context})=>{
 await seedStorage(context,page);await page.goto('/apps');await seedCatalog(page);
 await page.locator('[data-filter="all"]').dispatchEvent('click');
 await expect(page.locator('c-app-card')).toHaveCount(1);
 await expect(page.locator('c-app-card')).toContainText('Independent app');
 await page.locator('[data-filter="approved"]').dispatchEvent('click');
 await expect(page.locator('c-app-card')).toHaveCount(0);
});
