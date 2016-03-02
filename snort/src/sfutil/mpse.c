/*
*  $Id$
*
*   mpse.c
*    
*   An abstracted interface to the Multi-Pattern Matching routines,
*   thats why we're passing 'void *' objects around.
*
*   Copyright (C) 2002 SourceFire, Inc
*   Marc A Norton <mnorton@sourcefire.com>
*
**  
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "bitop.h"
#include "mwm.h"
#include "acsmx.h"
#include "acsmx2.h"
#include "sfksearch.h"
#include "mbom.h"
#include "mbom2.h"
#include "mpse.h"

#include "profiler.h"
#ifdef PERF_PROFILING
#include "snort.h"
PreprocStats mpsePerfStats;
#endif


// these two must correspond:
#define AUTO_DEFAULT MPSE_ACF
#define AUTO_DEFAULT_AC ACF_FULL


static UINT64 s_bcnt=0;

typedef struct _mpse_struct {

  int    method;
  void * obj;

}MPSE;

void * mpseNew( int method )
{
   MPSE * p;

   p = (MPSE*)malloc( sizeof(MPSE) );
   if( !p ) return NULL;

   p->method=method;
   p->obj   =NULL;
   s_bcnt  =0;

   switch( method )
   {
     case MPSE_MWM:
	p->obj = mwmNew();
        return (void*)p;
     case MPSE_AC:
       p->obj = acsmNew();
       return (void*)p;
     case MPSE_AUTO:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,AUTO_DEFAULT_AC);
       return (void*)p;
     case MPSE_ACF:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_FULL);
       return (void*)p;
     case MPSE_ACS:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSE);
       return (void*)p;
     case MPSE_ACB:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_BANDED);
       return (void*)p;
     case MPSE_ACSB:
       p->obj = acsmNew2();
       if(p->obj)acsmSelectFormat2((ACSM_STRUCT2*)p->obj,ACF_SPARSEBANDS);
       return (void*)p;
     case MPSE_KTBM:
     case MPSE_LOWMEM:
	p->obj = KTrieNew();
       return (void*)p;
     case MPSE_MBOM:
	p->obj = mbomNew();
       return (void*)p;
     case MPSE_MBOM2:
	p->obj = mbomNew2();
       return (void*)p;     
     default:
       return 0;
   }
}


void   mpseFree( void * pvoid )
{
  MPSE * p = (MPSE*)pvoid;
 
  switch( p->method )
   {
     case MPSE_AC:
       if(p->obj)acsmFree(p->obj);
       free(p);
       return;
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       if(p->obj)acsmFree2(p->obj);
       free(p);
       return;
     case MPSE_MWM:
       if(p->obj)mwmFree(p->obj);
       free( p );
       return;
     case MPSE_KTBM:
     case MPSE_LOWMEM:
       return; //no free? - JK
     case MPSE_MBOM:
       if(p->obj) mbomFree((MBOM_STRUCT *)p->obj);
       free(p);
       return;
     case MPSE_MBOM2:
       if(p->obj) mbomFree2((MBOM_STRUCT2 *)p->obj);
       free(p);
       return;
     case MPSE_AUTO:
       // Shouldn't get here if compiled mpsePrepPatterns must be called
       // Because method is always reset to something else after compile
       free(p);
       return;
     default:
       return;       
   }
}

int  mpseAddPattern ( void * pvoid, void * P, int m, 
             unsigned noCase,unsigned offset, unsigned depth,  void* ID, int IID )
{
  MPSE * p = (MPSE*)pvoid;

  switch( p->method )
   {
     case MPSE_AC:
       return acsmAddPattern( (ACSM_STRUCT*)p->obj, (unsigned char *)P, m,
              noCase, offset, depth, ID, IID );
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
     case MPSE_AUTO:
       return acsmAddPattern2( (ACSM_STRUCT2*)p->obj, (unsigned char *)P, m,
              noCase, offset, depth, ID, IID );
     case MPSE_MWM:
       return mwmAddPatternEx( p->obj, (unsigned char *)P, m, 
              noCase, offset, depth, (void*)ID, IID );
     case MPSE_KTBM:
     case MPSE_LOWMEM:
       return KTrieAddPattern( (KTRIE_STRUCT *)p->obj, (unsigned char *)P, m, 
              noCase, ID );
     case MPSE_MBOM:
       return mbomAddPattern( (MBOM_STRUCT *)p->obj, (unsigned char *)P, m, 
              noCase, offset, depth, (void*)ID, IID );
     case MPSE_MBOM2:
       return mbomAddPattern2( (MBOM_STRUCT2 *)p->obj, (unsigned char *)P, m, 
              noCase, offset, depth, (void*)ID, IID );
     default:
       return -1;
     break; 
   }
}

void mpseLargeShifts   ( void * pvoid, int flag )
{
  MPSE * p = (MPSE*)pvoid;
 
  switch( p->method )
   {
     case MPSE_MWM:
       mwmLargeShifts( p->obj, flag );
     break; 
     
     default:
       return ;
     break; 
   }
}

//#define AUTO_MAX_STATES 8192

int  mpsePrepPatterns  ( void * pvoid )
{
  MPSE * p             = (MPSE *)pvoid;
  ACSM_STRUCT2 * acsm  = NULL;
  MBOM_STRUCT  * mbom  = NULL;
  ACSM_PATTERN2 * plist  = NULL;
#ifdef AUTO_MAX_STATES
  MBOM_STRUCT2 * mbom2 = NULL;
#endif
  
  switch( p->method )
   {
     case MPSE_AC:
       return acsmCompile((ACSM_STRUCT*)p->obj);
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       return acsmCompile2((ACSM_STRUCT2*)p->obj);
     case MPSE_MWM:
       return mwmPrepPatterns(p->obj);
     case MPSE_KTBM:
     case MPSE_LOWMEM:
       return KTrieCompile((KTRIE_STRUCT *)p->obj);
     case MPSE_MBOM:
       return mbomCompile((MBOM_STRUCT *)p->obj);
     case MPSE_MBOM2:
       return mbomCompile2((MBOM_STRUCT2 *)p->obj);
     case MPSE_AUTO:
       acsm = (ACSM_STRUCT2*)p->obj;
       if(acsm != NULL) {
         if(acsm->minLen > 2) { // shortest pattern is length 3 or above

#ifdef AUTO_MAX_STATES
           // use mbom because it's faster on avg
           if(acsm->acsmNumStates > AUTO_MAX_STATES) {
             // use mbom2 to save mem
             mbom2 = p->obj = mbomNew2();
             p->method = MPSE_MBOM2;
             // move patterns into new struct
             for (plist = acsm->acsmPatterns; plist != NULL; plist = plist->next) {
               mbomAddPattern2(mbom2, plist->casepatrn, plist->n, plist->nocase,
                          plist->offset, plist->depth, plist->id, plist->iid);
             }
             acsmFree2(acsm);
             return mbomCompile2(mbom2);
           }
#endif
           // otherwise use normal mbom
           mbom = p->obj = mbomNew();
           p->method = MPSE_MBOM;
           // move patterns into new struct
           for (plist = acsm->acsmPatterns; plist != NULL; plist = plist->next) {
             mbomAddPattern(mbom, plist->casepatrn, plist->n, plist->nocase,
                        plist->offset, plist->depth, plist->id, plist->iid);
           }
           acsmFree2(acsm);
           return mbomCompile(mbom);

         }
         else {

           p->method = AUTO_DEFAULT; // go on using the ACSM
           return acsmCompile2(acsm);

         }
       }
     default:
       return 1;
   }
}

void mpseSetRuleMask ( void *pvoid, BITOP * rm )
{
  MPSE * p = (MPSE*)pvoid;

  switch( p->method )
  {
     case MPSE_MWM:
       mwmSetRuleMask( p->obj, rm );
     break;
     
     default:
       return ;
     break; 
  }
}
int mpsePrintDetail( void *pvoid )
{
  MPSE * p = (MPSE*)pvoid;

  switch( p->method )
  {
     case MPSE_AC:
      return acsmPrintDetailInfo( (ACSM_STRUCT*) p->obj );
     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
      return acsmPrintDetailInfo2( (ACSM_STRUCT2*) p->obj );
     case MPSE_MWM:
      return 0;
     case MPSE_LOWMEM:
       return 0;
     case MPSE_MBOM:
       mbomPrintDetailInfo((MBOM_STRUCT *)p->obj); break;
     case MPSE_MBOM2:
       mbomPrintDetailInfo2((MBOM_STRUCT2 *)p->obj); break;
     default:
       return 1;
  }

  return 0;
}	


int mpsePrintSummary(void * pvoid)
{
   acsmPrintSummaryInfo();
   acsmPrintSummaryInfo2();
   mbomPrintSummaryInfo();
   mbomPrintSummaryInfo2();
   return 0;
}

int mpseSearch( void *pvoid, unsigned char * T, int n, 
    int ( *action )(void*id, int index, void *data), 
    void * data ) 
{
  MPSE * p = (MPSE*)pvoid;
  int ret;
  PROFILE_VARS;

  s_bcnt += n;
  
  switch( p->method )
   {
     case MPSE_AC:
       PREPROC_PROFILE_START(mpsePerfStats);
       ret = acsmSearch( (ACSM_STRUCT*) p->obj, T, n, action, data );
       PREPROC_PROFILE_END(mpsePerfStats);
       return ret;

     case MPSE_ACF:
     case MPSE_ACS:
     case MPSE_ACB:
     case MPSE_ACSB:
       PREPROC_PROFILE_START(mpsePerfStats);
       ret = acsmSearch2( (ACSM_STRUCT2*) p->obj, T, n, action, data );
       PREPROC_PROFILE_END(mpsePerfStats);
       return ret;

     case MPSE_MWM:
       PREPROC_PROFILE_START(mpsePerfStats);
       ret = mwmSearch( p->obj, T, n, action, data );
       PREPROC_PROFILE_END(mpsePerfStats);
       return ret;

     case MPSE_LOWMEM:
       PREPROC_PROFILE_START(mpsePerfStats);
       ret = KTrieSearch( (KTRIE_STRUCT *)p->obj, T, n, action, data );
       PREPROC_PROFILE_END(mpsePerfStats);
       return ret;
      
     case MPSE_MBOM:
       PREPROC_PROFILE_START(mpsePerfStats);
       ret = mbomSearch( (MBOM_STRUCT *)p->obj, T, n, action, data );
       PREPROC_PROFILE_END(mpsePerfStats);
       return ret;
      
     case MPSE_MBOM2:
       PREPROC_PROFILE_START(mpsePerfStats);
       ret = mbomSearch2( (MBOM_STRUCT2 *)p->obj, T, n, action, data );
       PREPROC_PROFILE_END(mpsePerfStats);
       return ret;

     case MPSE_AUTO:
       // should never happen
     default:
       //PREPROC_PROFILE_START(mpsePerfStats); // take out -JK
       return 1;

   }

}


UINT64 mpseGetPatByteCount( )
{
  return s_bcnt; 
}

void mpseResetByteCount( )
{
    s_bcnt = 0;
}

 
