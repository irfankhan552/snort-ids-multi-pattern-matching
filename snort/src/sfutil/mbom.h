/*
**   MBOM.H (MultiBOM - or Multi Backwards Oracle Matching)
**
**   Version 1.0
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "acsmx.h"

#ifndef MBOM_H
#define MBOM_H

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


/* A state/node in a DAWG/Oracle/Trie */

typedef struct _mbom_node {
  /* allocate 256 pointers to other nodes for constant time branching in the automaton */

  struct _mbom_node * next_states[ALPHABET_SIZE]; 
  struct _mbom_node * supply_state;

  /* 256 bit table where 1s = extended transition at same index in next_states */
  /* If next_states[i] != NULL and 0 == bit i in the table is 0 then this node
   * owns the node at next_states[i] and is responsible for deleting it */

  uint8_t             extendedTransitions[ALPHABET_SIZE / 8];
  uint16_t id;

} MBOM_NODE; /* SIZE: 1038 B (actual memory consumption depends on compiler settings) */


/*
*   MultiBOM Matcher Struct - one per group of pattterns
*/
typedef struct {
  
	ACSM_STRUCT   * acsm;          /* an Aho-Corasick Std state machine */
	MBOM_NODE     * initialState;  /* root node */
	uint32_t      mbomSize;        /* number of states/nodes */
	uint32_t      mbomNumTrans;    /* number of transitions */
	uint32_t      mbomNumPatterns; /* number of patterns in the list */
	uint8_t       mbomFormat;      /* the automaton format either an Oracle or a DAWG */
	uint16_t      minLen;          /* length of the shortest pattern */
	uint16_t      matches;

}MBOM_STRUCT;

/*
*   Prototypes
*/

MBOM_STRUCT * mbomNew();

int  mbomAddPattern(MBOM_STRUCT * mbom, unsigned char * pat, int n,
		  int nocase, int offset, int depth, void *  id, int iid);

int  mbomCompile(MBOM_STRUCT * mbom);

int  mbomSearch(MBOM_STRUCT * mbom, unsigned char * T, int n, 
		  int (*Match)(void * id, int index, void * data), void * data);

void mbomFree(MBOM_STRUCT * mbom);

int  mbomSelectFormat(MBOM_STRUCT * mbom, int format);

void mbomSetVerbose(int n);

void mbomPrintDetailInfo(MBOM_STRUCT * mbom);

void mbomPrintSummaryInfo();

#endif
