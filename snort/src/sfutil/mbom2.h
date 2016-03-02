/*
**   MBOM.H (MultiBOM - or Multi Backwards Oracle Matching)
**
**   Version 2.0
**
**   Copyright (C) 2006 James Kelly james@jameskelly.net
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acsmx.h"
#include "hashtable.h"

#ifndef MBOM2_H
#define MBOM2_H

#ifdef WIN32

#ifdef inline
#undef inline
#endif

#define inline __inline

#endif

/*
*   DEFINES and Typedef's
*/
#define ALPHABET_SIZE 256

#define MBOM_ROOT 1

#define MBOM_VERBOSE 1
#define MBOM_NON_VERBOSE 0

#ifndef MBOM_EASYTYPES
#define MBOM_EASYTYPES

typedef unsigned int uint32_t;
typedef unsigned short uint16_t;
typedef unsigned char uint8_t;

enum {
  MBOM_ORACLE, // keep first (0) entry default
  MBOM_DAWG,
};

#endif

typedef struct hashtable HASHTABLE;
typedef struct hashtable_itr HASHTABLE_ITR;

typedef uint16_t MBOM_STATE;

/* A state/node in a DAWG/Oracle/Trie */

typedef struct {
  MBOM_STATE from_state;
  uint8_t  character;
} MBOM_KEY;

// MBOM_VALUE is just a MBOM_STATE as next_state

/*
*   MultiBOM Matcher Struct - one per group of pattterns
*/
typedef struct {
  /* instead of allocating 256 pointers to other nodes for constant time
   * branching in the automaton we use a hashtable */
  HASHTABLE   * transitions;
  ACSM_STRUCT * acsm;          /* an Aho-Corasick Std state machine */
  
  uint32_t    mbomSize;        /* number of states/nodes */
  uint32_t    mbomNumTrans;    /* number of transitions */
  uint32_t    mbomNumPatterns; /* number of patterns in the list */
  uint8_t     mbomFormat;      /* the automaton format either an Oracle or a DAWG */
  uint16_t    minLen;          /* length of the shortest pattern */

}MBOM_STRUCT2;

/*
*   Prototypes
*/
MBOM_STRUCT2 * mbomNew2();
int  mbomAddPattern2(MBOM_STRUCT2 * mbom, unsigned char * pat, int n,
                    int nocase, int offset, int depth, void *  id, int iid);
int  mbomCompile2(MBOM_STRUCT2 * mbom);
int  mbomSearch2(MBOM_STRUCT2 * mbom, unsigned char * T, int n, 
		  int (*Match)(void * id, int index, void * data),
                  void * data);
void mbomFree2(MBOM_STRUCT2 * mbom);
int  mbomSelectFormat2(MBOM_STRUCT2 * mbom, int format);
void mbomSetVerbose2(int n);
void mbomPrintDetailInfo2(MBOM_STRUCT2 * mbom);
void mbomPrintSummaryInfo2();

// make these available for the hashtable memory tracking:
void * MBOM_MALLOC2(uint32_t size);
void * MBOM_REALLOC2(void * p, uint32_t new_size, uint32_t difference);
void MBOM_FREE2(void * p, uint32_t size);

#endif
