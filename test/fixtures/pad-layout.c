#define _GNU_SOURCE
#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
static size_t fail_size;
static void *layout_malloc(size_t n) { return n == fail_size && fail_size ? NULL : malloc(n); }
#define malloc layout_malloc
#include "shielded-pads.c"
#undef malloc

int main(int argc,char **argv) {
    assert(argc==2);
    uint8_t pk[32],sk[32],sid[16]={2},digest[32]={3}; crypto_box_keypair(pk,sk);
    sh_pads_group group={.group=0,.K=2,.u_len=3};strcpy(group.name,"layout.weight");
    char path[1024],bad[1024];snprintf(path,sizeof path,"%s/good.pads",argv[1]);snprintf(bad,sizeof bad,"%s/bad.pads",argv[1]);
    int err;const int32_t u[3]={1,2,3};
    sh_pads_writer *w=sh_pads_writer_open(path,digest,sid,&group,1,0,1,pk,&err);assert(w && !err);
    uint8_t key[32];memcpy(key,w->key,32);sh_pads_hdr header=w->hdr;
    assert(sh_pads_writer_cell(w,0,0,u)==0);assert(sh_pads_writer_close(w)==0);
    sh_pads_reader r={0};memcpy(r.seed_id,sid,16);memcpy(r.sk,sk,32);
    sh_pads_file f;assert(file_open(&r,path,&f)==SH_OK);file_close(&f);
    uint64_t off,row,len;
    assert(shipment_layout(&group,1,1,false,&off,&row,&len) && off==4096 && row==25 && len==4121);
    /* format 4 (keyed cells): each cell carries its 32-byte mask key ahead of u */
    { uint64_t koff,krow,klen; assert(shipment_layout(&group,1,1,true,&koff,&krow,&klen) && koff==4096 && krow==25+32 && klen==4096+57); }
    for(int kind=0;kind<10;kind++) {
        sh_pads_hdr h=header;sh_pads_group g=group;
        if(kind==0)h.data_off=0;
        if(kind==1)h.data_off=UINT64_MAX;
        if(kind==2)h.data_off+=4096;
        if(kind==3)h.row_bytes=UINT64_MAX;
        if(kind==4)g.u_len=UINT64_MAX;
        if(kind==5)g.u_len=0;
        if(kind==6)g.u_len=(UINT64_C(64)*UINT32_MAX)/3+1;
        if(kind==7){g.u_len=(UINT64_C(64)*UINT32_MAX)/3;h.row_bytes=cell_bytes(g.u_len);h.index_count=SH_PADS_INDEX_LIMIT;}
        uint8_t hash[64],nonce[12];assert(header_hash(&h,&g,1,hash)==0);hdr_nonce(nonce);assert(aead_seal(key,nonce,hash,64,h.hdr_box)==0);
        // These headers have VALID AEAD authentication under the recipient's
        // boxed shipment key, so format rejection cannot hide behind a bad tag.
        int fd=open(bad,O_RDWR|O_CREAT|O_TRUNC,0600);assert(fd>=0);
        assert(pwrite(fd,&h,sizeof h,0)==sizeof h);assert(pwrite(fd,&g,sizeof g,sizeof h)==sizeof g);
        assert(ftruncate(fd,(off_t)(len+(kind==8 ? -1 : kind==9 ? 1 : 0)))==0);close(fd);
        assert(file_open(&r,bad,&f)==SH_ERR_VERIFY);
    }
    // Writer must reject arithmetic/counter overflow before allocations or opening/truncating the output.
    assert(unlink(bad)==0);
    for(int kind=0;kind<3;kind++) {
        sh_pads_group groups[3]={group,group,group};
        for(int i=0;i<3;i++)groups[i].u_len=kind==0 ? UINT64_MAX : kind==1 ? 0 : (UINT64_C(64)*UINT32_MAX)/3;
        uint64_t count=kind==2 ? SH_PADS_INDEX_LIMIT : 1;
        assert(!sh_pads_writer_open(bad,digest,sid,groups,kind==2 ? 3 : 1,0,count,pk,&err) && err==SH_ERR_RANGE);
        assert(access(bad,F_OK)!=0);
    }
    // A failed header hash used to become a known all-zero digest. Forge that
    // authenticated zero digest and force the precise allocation to fail.
    sh_pads_hdr h=header;uint8_t zeros[64]={0},nonce[12];hdr_nonce(nonce);
    assert(aead_seal(key,nonce,zeros,64,h.hdr_box)==0);
    int fd=open(bad,O_RDWR|O_CREAT|O_TRUNC,0600);assert(fd>=0);
    assert(pwrite(fd,&h,sizeof h,0)==sizeof h);assert(pwrite(fd,&group,sizeof group,sizeof h)==sizeof group);
    assert(ftruncate(fd,(off_t)len)==0);close(fd);
    fail_size=sizeof h+sizeof group;
    uint8_t hash[64];memset(hash,0xa5,sizeof hash);
    assert(header_hash(&h,&group,1,hash)==SH_ERR_NOMEM);
    for(size_t i=0;i<sizeof hash;i++)assert(hash[i]==0xa5);
    assert(file_open(&r,bad,&f)==SH_ERR_NOMEM);
    // Existing paths fail before hashing. Use a fresh path to exercise the
    // injected header-hash allocation failure, and retain the old file check.
    assert(!sh_pads_writer_open(path,digest,sid,&group,1,0,1,pk,&err) && err==SH_ERR_IO);
    char fresh[1024];snprintf(fresh,sizeof fresh,"%s/hash-allocation.pads",argv[1]);
    assert(!sh_pads_writer_open(fresh,digest,sid,&group,1,0,1,pk,&err) && err==SH_ERR_NOMEM);
    assert(access(fresh,F_OK)!=0);
    fail_size=0;
    assert(file_open(&r,path,&f)==SH_OK);file_close(&f);  // failed writer preserved the previous file
    puts("pad-layout: ok");
}
