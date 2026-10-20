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
test('public catalog refuses direct access to delisted releases',async({page,context})=>{
 await seedStorage(context,page);await page.goto('/apps?app='+appId);
 await page.waitForSelector('#appDetailView',{state:'attached'}).catch(()=>{});
 const result=await seedCatalog(page);
 expect(result.visible).toEqual([]);expect(result.recommended).toBe(-1);
 expect(result.result.error).toContain('delisted');
 await expect(page.locator('c-app-detail')).toHaveCount(0);
 await expect(page.locator('#appDetailView')).toContainText('isn’t in the catalog');
});
test('public store has no moderation-bypass All releases tab',async({page,context})=>{
 await seedStorage(context,page);await page.goto('/apps');await seedCatalog(page);
 await expect(page.locator('[data-filter="all"]')).toHaveCount(0);
 await page.locator('[data-filter="approved"]').dispatchEvent('click');
 await expect(page.locator('c-app-card')).toHaveCount(0);
});
