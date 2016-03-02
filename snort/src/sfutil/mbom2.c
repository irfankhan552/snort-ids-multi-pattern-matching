/*
**   $Id$
** 
**   mbom2.c
**
**   Multi-Pattern Search Engine
**
**   MultiBOM - or Multi Backwards Oracle Matching
**
**   Version 2.0
**
**   Copyright (C) 2006 James Kelly james@jameskelly.net
**
**   Reference: (Original MultiBOM proposal) - IN FRENCH
**   C. Allauzen and M. Raffinot. Oracle des facteurs d'un ensemble de mots.
**   Technical Report IGM 99-11, Institut Gaspard Monge, Universite de 
**   Marne-la-Vallee, France, 1999.
**   
**   Reference: (BEST REFERENCE FOR SBOM and how to build a factor oracle)
**   G. Navarro and M. Raffinot. Flexible Pattern Matching in Strings, 
**   Practical On-line Search Algorithms for Texts and Biological Sequences.
**   Cambridge University Press, Cambridge, UK, 2002
**
**   Reference: (BEST REFERENCE FOR MultiBDM)
**   M. Crochemore and W. Rytter. Text Algorithms. Oxford University Press, 1994.
**   Pages 140-143 *Example in book has a mistake in it; one pattern is not matched*
**   
**   Reference:
**   M. Raffinot. On the multi backward DAWG matching algorithm (MultiBDM). In
**   R. Baeza-Yates, editor, WSP'97: Proceedings of the 4th South American Work-
**   shop on String Processing, pages 149{165, Valparaiso, Chile, Nov. 1997. 
**   Carleton University Press.
**
**   Version 1.0 Notes - James Kelly:
**
**   1) Finds all occurrences of all patterns within a text.
**
**   2) Currently supports only the use of a factor oracle; however, MultiDAWG 
**      uses the same approach with a DAWG (Directed Acyclic Word Graph)
** 
**   3) MBOM is an implementation of MultiBOM from first reference. It
**      is for use in Snort and uses Snort's standard version of its
**      Aho-Corasick state machine (acsmx.h/c).
**
**   4) MBOM doesn't take much extra memory compared to Snort's standard
**      Aho-Corasick state machine pattern matcher; however, the running time
**      will greatly be *enhanced* (faster) because MBOM is average case
**      and worst case optimal. That is, it's sublinear (wrt text length)
**      on average and linear (wrt text length) in the worst case. The
**      average case is defined as only indepedent equiprobable characters
**      appearing in the search text. The MBOM algorithm executes at most
**      2n inspections of search text characters where the search text
**      length is n.
**
**   5) MBOM uses a window size of length equal to the minimum length
**      pattern. Therefore, shifts are limited by this window size.
**      Thus, it is not/hardly worth using the MBOM algorithm unless
**      the minimum length pattern is at least of length 3. Note that
**      for those cases the Aho-Corasick algorithm would be faster.
**
**   New Version 2.0 Notes - James Kelly:
**
**   1) This version uses a hashtable and there is no trie or nodes. It is
**      all virtual in the hashtable which of course saves a lot (tons) of
**      memory. For comparison for the Snort default rule DB MBOM v1.0 
**      would take 14331.21 KB of memory + 157366.49 KB for the Aho-Corasick
**      State Machine - ACSM), but MBOM v2.0 takes 548.70Kbytes + the same 
**      for the ACSM. In the memory usage of the factor oracle there's a 
**      difference of 26:1 (ratio)!
**
**   2) Still only supports only the use of a factor oracle; however, MultiDAWG 
**      uses the same approach with a DAWG (Directed Acyclic Word Graph).
** 
**   3) States in the factor oracle are represented by a uint16_t therefore we
**      are limited to 2^16 states. That should be plenty considering the factor 
**      oracle's depth is cut off at the length of the shortest pattern. It should
**      be easy to change it to a uint32_t if needed, but of course this will 
**      increase memory cost per state as well.
**
**   4) The hashtable holds a state id and character as a key, and another state 
**      id as the value. The character is the label on the transition between the
**      two states.
**
**   5) MBOM v1.0 stored the supply state in the NODE which meant it was kept around
**      after pre-computation, but it actually isn't needed. In this version the
**      memory to hold the supply function (supply states) is only allocated during
**      precomputation (the compile routine). Before the search phase it is deleted.
**
**
*/  
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
  
#include "mbom2.h"

//#define DEBUG_MBOM2

/*
* facilitates: memory checks
*/ 
#define MEMASSERT(p,s) if(!p){printf("MBOM-No Memory: %s!\n",s);exit(0);}

/*
* Keep this for stats:
*/ 
static int max_memory = 0;

/*
* toggle verbose for all instances of MBOM2
*/ 
static int s_verbose = MBOM_NON_VERBOSE;

/*
* Keep this summary for stats:
*/ 
typedef struct mbom_summary_s
{
      unsigned    num_states;
      unsigned    num_transitions;
      unsigned    num_patterns;
      unsigned    num_groups;

} mbom_summary_t;

static mbom_summary_t summary={0,0,0,0}; 


/* QUEUE STUFF:
*  A Queue is needed to do a breadth-first traversal
*  of our trie to make a factor oracle.
*/

/*
*    Simple QUEUE NODE
*/ 
typedef struct _qnode
{
  MBOM_STATE * state; //data
  MBOM_KEY   * parent; //data
  struct _qnode *next;
} QNODE;

/*
*    Simple QUEUE Structure
*/ 
typedef struct _queue
{
  QNODE * head, *tail;
  int count;
} QUEUE;

/*
*   Initialize the queue
*/ 
static void
queue_init (QUEUE * s) 
{
  s->head = s->tail = 0;
  s->count= 0;
}

/*
*  Add Tail Item to queue (FiFo/LiLo)
*/ 
static void queue_add (QUEUE * s, MBOM_STATE * state, MBOM_KEY * parent)
{
  QNODE * q;

  if (!s->head)
  {
      // don't count this in summary it will be deleted (it's tmp only)
      // a queue is never kept during the search only used for 
      // precomputation/preprocessing purposes.
      q = s->tail = s->head = (QNODE *)malloc(sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->state     = state;
      q->parent    = parent;
      q->next      = NULL;
  }
  else
  {
      q = (QNODE *) malloc (sizeof (QNODE)); //don't count this in summary
      q->state      = state;
      q->parent     = parent;
      q->next       = NULL;
      s->tail->next = q;
      s->tail       = q;
  }
  ++(s->count);
}


/*
*  Remove Head Item from queue
*/
static void queue_remove (QUEUE * s, MBOM_STATE ** state, MBOM_KEY ** parent) 
{
  void * data;
  QNODE * q;
  
  data = NULL;
  
  if (s->head)
  {
      q       = s->head;
      *state  = q->state;
      *parent = q->parent;
      s->head = s->head->next;
      --(s->count);

      if( !s->head )
      {
	  s->tail = NULL;
	  s->count = 0;
      }
      free (q);
  }
}

/*
*   Return # of items in the queue
*/ 
static int
queue_count (QUEUE * s) 
{
  return s->count;
}


/*
*  Free the queue
*/ 
static void
queue_free (QUEUE * s) 
{
  QNODE * q;
  
  while (s->head)
    {
      q = s->head;
      s->head = q->next;
      s->count--;
      free (q);
      
      if( !s->head ) {
        s->tail = NULL;
        s->count = 0;
      }
    }
}

/** HASHTABLE STUFF **/

DEFINE_HASHTABLE_INSERT(insert_node, MBOM_KEY, MBOM_STATE);
DEFINE_HASHTABLE_SEARCH(get_node, MBOM_KEY, MBOM_STATE);
DEFINE_HASHTABLE_REMOVE(remove_node, MBOM_KEY, MBOM_STATE);

/*
* Returns the hash value of a key:
*/

static unsigned int
hashFromKey(void *ky)
{
  MBOM_KEY * k = (MBOM_KEY *)ky;
  //uint32_t i = k->from_state;
  //uint32_t j = k->character;
  
  //return (i ^ j); // (fastest)
  return (((k->from_state << 7) | (k->from_state >> 5)) ^ k->character); // (faster)
  //return (((i << 7) | (i >> 5)) ^ j) + (i * 17) + (j * 4901); //4901 = 13*29 (good)
}

/*
*  Check equality between two keys:
*
*  DO NOT USE return (0 == memcmp(k1, k2, sizeof(MBOM_KEY))) in this function
*  unless you have checked the sizeof value for the key
*
*  Our key is actually 3B but sizeof(MBOM_KEY) returns 4B !!
*  this is due to structure field packaging in gcc which screws it up big time
*  because sometimes get_node would return NULL when it shouldn't
*  
*/
static int
equalKeys(void *k1, void *k2)
{
  MBOM_KEY * kk1 = (MBOM_KEY *)k1, * kk2 = (MBOM_KEY *)k2;
  return (kk1->from_state == kk2->from_state && kk1->character == kk2->character);
}


/* MBOM STUFF */

/*
* Case Translation Table
*/ 
static unsigned char xlatcase[256];

/*
* Init Case Translation Table
*/ 
static void init_xlatcase() 
{
  int i;
  for (i = 0; i < 256; i++)
    {
      xlatcase[i] = toupper(i);
    }
}

#ifndef MBOM_MEM_STATS
#define MBOM_MEM_STATS
/*
* measure memory allocations
*/ 
void * MBOM_MALLOC2 (uint32_t size)
{
  void * p;
  p = malloc (size);
  if (p) {
    max_memory += size;
  }
  return p;
}

/*
* measure memory reallocations
* (only used by the hashtable in special circumstances where low on mem)
*/
void * MBOM_REALLOC2 (void * p, uint32_t new_size, uint32_t difference)
{
  realloc (p, new_size);
  if (p) {
    max_memory += difference;
  }
  return p;
}

/*
* measure memory deallocations
*/
void MBOM_FREE2 (void * p, uint32_t size) 
{
  if (p) {
    free (p);
    max_memory -= size;
  }
}
#endif

/*
* toggle between verbose mode on/off with 1/0
*/ 
void mbomSetVerbose2(int n)
{
  s_verbose = n;
}

/*
*   Select the desired storage mode
*/
int mbomSelectFormat2(MBOM_STRUCT2 * mbom, int format)
{
  switch( format )
  {
    case MBOM_ORACLE:
    case MBOM_DAWG:
      mbom->mbomFormat = MBOM_ORACLE; // only support this currently
      break;
    default:
      return -1; //doesn't even matter right now (only one version coded)
  }

  return 0;
}

/*
*  Create a new MultiBOM Matcher struct
*/ 
MBOM_STRUCT2 * mbomNew2() 
{
  MBOM_STRUCT2 * mbom;

  init_xlatcase();

  mbom = (MBOM_STRUCT2 *) MBOM_MALLOC2(sizeof (MBOM_STRUCT2));
  MEMASSERT (mbom, "mbomNew");
  memset (mbom, 0, sizeof (MBOM_STRUCT2));
  
  mbom->transitions = create_hashtable(16, hashFromKey, equalKeys);
  MEMASSERT (mbom->transitions, "mbomNew (HT)");
  
  mbom->acsm = acsmNew();
  MEMASSERT (mbom->acsm, "mbomNew (acsm)");

  ++(summary.num_groups);
  
  return mbom;
}

/*
*   Add a pattern to the list of patterns for this instance
*/ 
int mbomAddPattern2(MBOM_STRUCT2 * mbom, unsigned char * pat, int n, int nocase,
		int offset, int depth, void * id, int iid) 
{
  if(n <= 0) {
    printf("Illegal pattern length found of: %d\n", n);
    exit(0);
  }
  
  if(mbom->minLen == 0 || mbom->minLen > n) {
    mbom->minLen = n; // keep track of the length of the shortest pattern
  }
  
  acsmAddPattern(mbom->acsm, pat, n, nocase, offset, depth, id, iid);
  ++(mbom->mbomNumPatterns);
  ++(summary.num_patterns);
  return 0;
}

#ifdef DEBUG_MBOM2
/*
*   Prints out the factor oracle structure:
*
*   This prints out the F.O. the same way as v1.0
*   for comparison purposes (they should be the same)
*/
static void printMbom2(MBOM_STRUCT2 * mbom)
{
  QUEUE q;
  MBOM_STATE * next_state;
  MBOM_KEY tmpKey, * key;
  int j;
  
  printf("\nMBOM structure:\n");
  
  /* use queue to facilitate a breadth first traversal over the node/states
   * of the trie to print them */
  queue_init(&q);
  
  tmpKey.from_state = MBOM_ROOT;
  
  for(j = 0; j < ALPHABET_SIZE; ++j) {
    tmpKey.character = j;
    
    if((next_state = get_node(mbom->transitions, &tmpKey)) != NULL) {
      //key = (MBOM_KEY * )malloc(sizeof(MBOM_KEY));
      //key->character = j;
      //key->from_state = MBOM_ROOT;
      queue_add(&q, next_state, NULL);
      printf("t(%d,%x) = %d\n", MBOM_ROOT, j, *next_state);
    }
  }
  
  while(queue_count(&q)) {
    
    queue_remove(&q, &next_state, &key);
    tmpKey.from_state = *next_state;
    
    for(j = 0; j < ALPHABET_SIZE; ++j) {
      tmpKey.character = j;
      if((next_state = get_node(mbom->transitions, &tmpKey)) != NULL) {
        queue_add(&q, next_state, NULL);
        printf("t(%d,%x) = %d\n", tmpKey.from_state, j, *next_state);
      }
    }
  }

  queue_free(&q);
  printf("\n");
}
#endif

/*
*   Compile (Construct) the automaton to be used for this pattern matcher
*
*   Currently this function always builds a factor oracle, 
*   but a DAWG could also be used
*
*   The resulting factor oracle recognizes at least all of the factors
*   of the pattern set P. It's construction time should be O(|P|) (linear).
*
*   For instructions on how to build this see the algorithm references/notes above
*/
int mbomCompile2(MBOM_STRUCT2 * mbom)
{  
  int              j;
  ACSM_PATTERN     * plist;
  MBOM_STATE       current = 0, * cur = NULL, * next_state = NULL; // states
  QUEUE            q; // temp for Breadth-First Traversal
  MBOM_KEY         * key, tmpKey, * parent;
  MBOM_STATE       * supplyFnc;     /* Only used in precomputation */
  
  /* Create Trie: */
  /* ------------ */
  
  ++(mbom->mbomSize); // Initial State
  
  for (plist = mbom->acsm->acsmPatterns; plist != NULL; plist = plist->next) {
    current = MBOM_ROOT; // Initial State
    j = plist->n - 1; //start at the end of the patttern because we're entering it reversed
    
    tmpKey.from_state = current;
    tmpKey.character = plist->patrn[j];
    
    while(j >= 0 && (next_state = get_node(mbom->transitions, &tmpKey)) != NULL) {
      tmpKey.from_state = current = *next_state;
      tmpKey.character = plist->patrn[--j];
    }
    
    while(j >= 0) {
      key = (MBOM_KEY *)MBOM_MALLOC2(sizeof(MBOM_KEY));
      MEMASSERT(key, "mbomCompile K");
      key->from_state = current;
      key->character = plist->patrn[j];
      
      next_state = (MBOM_STATE *)MBOM_MALLOC2(sizeof(MBOM_STATE));
      MEMASSERT(next_state, "mbomCompile V");
      *next_state = ++(mbom->mbomSize); // Add State
      ++(mbom->mbomNumTrans);  // Add Transition
      
      insert_node(mbom->transitions, key, next_state);
      current = *next_state;
      --j;
    }
  }

  /* Build Factor Oracle From Trie: */
  /* ------------------------------ */
  
  /* We need to create external transitions with a breadth first traversal */
  
  //don't count this memory because it will deleted after during this fnc
  supplyFnc = malloc((mbom->mbomSize + 1) * sizeof(MBOM_STATE));
  memset(supplyFnc, 0, (mbom->mbomSize + 1) * sizeof(MBOM_STATE)); // supply fnc 0 = NULL/NOTHING
  
  // use queue to facilitate a breadth first traversal over the
  // node/states of the trie to make the factor oracle
  queue_init(&q);
  
  tmpKey.from_state = MBOM_ROOT;
  for(j = 0; j < ALPHABET_SIZE; ++j) {
    tmpKey.character = j;
    
    if((next_state = get_node(mbom->transitions, &tmpKey)) != NULL) {
      parent = (MBOM_KEY * )malloc(sizeof(MBOM_KEY));
      parent->character = tmpKey.character;
      parent->from_state = tmpKey.from_state;
      queue_add(&q, next_state, parent);
    }
  }
  
  while(queue_count(&q)) {

    queue_remove(&q, &cur, &parent);
    
    // Process current node
    // tmpKey.from_state moves ("up") towards the root/initialState

    tmpKey.from_state = supplyFnc[parent->from_state];
    tmpKey.character = parent->character;
    
    while(tmpKey.from_state != 0 && get_node(mbom->transitions, &tmpKey) == NULL) {

      // Add an external transition
      key = (MBOM_KEY *)MBOM_MALLOC2(sizeof(MBOM_KEY));
      MEMASSERT(key, "mbomCompile K2");
      key->character = tmpKey.character;
      key->from_state = tmpKey.from_state;
      
      next_state = (MBOM_STATE *)MBOM_MALLOC2(sizeof(MBOM_STATE));
      MEMASSERT(next_state, "mbomCompile V2");
      *next_state = *cur;
      
      insert_node(mbom->transitions, key, next_state);      
      ++(mbom->mbomNumTrans);  // Add Transition

      tmpKey.from_state = supplyFnc[tmpKey.from_state];
    }

    if(tmpKey.from_state != 0) {
      next_state = get_node(mbom->transitions, &tmpKey);
      supplyFnc[*cur] = *next_state;
    }
    else {
      supplyFnc[*cur] = MBOM_ROOT;
    }
    
    free(parent); // no longer needed (tmp only)

    /* Enqueue all children nodes of current */
    tmpKey.from_state = *cur;
    for(j = 0; j < ALPHABET_SIZE; ++j) {
      tmpKey.character = j;
      if((next_state = get_node(mbom->transitions, &tmpKey)) != NULL) {
        parent = (MBOM_KEY * )malloc(sizeof(MBOM_KEY));
        parent->character = tmpKey.character;
        parent->from_state = tmpKey.from_state;
        queue_add(&q, next_state, parent);
      }
    }
  }
  
  queue_free(&q);
  free(supplyFnc); // wasn't counted in memory usage
  
  /* Tell the ACSM to compile itself too */
  /* ----------------------------------- */
  acsmCompile(mbom->acsm);
  
  /* Accrue Summary State Stats */
  summary.num_states      += mbom->mbomSize;
  summary.num_transitions += mbom->mbomNumTrans;


#ifdef DEBUG_MBOM2
  printMbom2(mbom);
  mbomPrintDetailInfo2(mbom);
#endif    

  return 0;
}


/**  Tc is declared once outside of this function is a pointer 
 **  into all converted uppercase text characters/bytes 
 **/
#define MBOM_MAX_TEXT 65536
static unsigned char Tc[MBOM_MAX_TEXT]; // should be more than enough space for snort

/*
*   Search Function
*/
int mbomSearch2(MBOM_STRUCT2 * mbom, unsigned char *Tx, int n,
           int (*Match) (void * id, int index, void *data), 
           void *data)
{
  int nfound     = 0; /* num of patterns found */
  int min        = mbom->minLen; // minimal length of patterns (also the window size)
  int i          = 0; // i is the position of the window on the text
  int critpos    = 0; // position of the input head of the ACSM
  int j          = 0; // tmp
  int end        = n - min + 1; // last valid i + 1
  int windowEnd  = min - 1;
  MBOM_STATE current  = 0;
  MBOM_STATE * tmp    = 0;
  HASHTABLE * trans   = mbom->transitions;
  MBOM_KEY tmpKey;
  
  int state          = 0; /* ACSM current state*/
  ACSM_PATTERN       * mlist; /* tmp list of patterns at a terminal state */
  ACSM_STATETABLE    * states = mbom->acsm->acsmStateTable;
  
  // Tc is declared once outside of this function is a pointer 
  // into all converted uppercase text characters/bytes
  
  if(n > MBOM_MAX_TEXT) {
    printf("mbom Search unperformed because text was too long");
    exit(0);
  }
  
  // Case conversion of text
  
  for (j = 0; j < n; ++j) {
    Tc[j] = xlatcase[ Tx[j] ]; 
  }

  while(i < end && critpos < n) {
    
    // Here's the ACSM has scanned up to but not including Tc[critpos]
    // We scan with the oracle back to and including Tc[critpos]

    j = i + windowEnd;
    current = MBOM_ROOT;
    
    // Search for factor mismatch in the oracle/dawg:
    tmpKey.character = Tc[j];
    tmpKey.from_state = current;
    tmp = get_node(trans, &tmpKey);
      
    while(j >= critpos && tmp != NULL) {    
      --j;
      tmpKey.character = Tc[j];
      tmpKey.from_state = *tmp; // new current
      tmp = get_node(trans, &tmpKey);
    }
    
    if(tmp == NULL) { //if it didn't make it all the way to the critpos
      state = 0; // reset ACSM
      critpos = j + 1;
    }
    
    // Search with ACSM between indexes critpos to n-1:
    
    while(critpos < n && (critpos < i + min || states[state].depth >= min)) {

      state = states[state].NextState[Tc[critpos]]; // scan one character      
      ++critpos;

      if(states[state].MatchList != NULL) { // if this state is terminal
      
        /* Go through the patterns that match at this state */

        for(mlist=states[state].MatchList; mlist != NULL; mlist = mlist->next) {

          /* j = location that match starts in Tx */
          j = critpos - mlist->n;
          
          /* obviously faster for patterns that are case insensitive */
          if(mlist->nocase) {
            ++nfound;
            if(Match (mlist->id, j, data))
              return nfound;
          }
          else {
            if(memcmp(mlist->casepatrn, Tx + j, mlist->n) == 0) {
              ++nfound;
              if(Match (mlist->id, j, data))
                return nfound;
            }
          }

        } //end for
      } //end if
    } //end while

    /* shift by critpos - length of longest prefix matched */
    i = critpos - states[state].depth; // SHIFT WINDOW
  }
  
  return nfound;
}


/*
*   Free all memory
*/ 
void mbomFree2(MBOM_STRUCT2 * mbom) 
{
  hashtable_destroy(mbom->transitions, 1); // deletes all states and transitions
  
  acsmFree(mbom->acsm); // deletes the ACSM
  
  MBOM_FREE2(mbom, sizeof(MBOM_STRUCT2));
  
  --(summary.num_groups);
}

/*
*   Prints information about a mbom matcher instance
*/
void mbomPrintDetailInfo2(MBOM_STRUCT2 * mbom)
{
    char * sf[]= {"Factor Oracle", "DAWG (Directed Acyclic Word Graph)"};
    
    printf("+--[Pattern Matcher:Multi Backward Oracle Matching (MultiBOM) Instance Info]------\n");
    printf("| Alphabet Size    : %u Chars\n", ALPHABET_SIZE);
    printf("| Size of State    : %u bytes\n", (int)(sizeof(MBOM_STATE)));
    printf("| Storage Format   : %s\n", sf[mbom->mbomFormat]);
    printf("| Shortest Pat Len : %u\n", (unsigned int)mbom->minLen);
    printf("| Num States       : %u\n", (unsigned int)mbom->mbomSize);
    printf("| Num Transitions  : %u\n", (unsigned int)mbom->mbomNumTrans);
    printf("| Num Patterns     : %u\n", (unsigned int)mbom->mbomNumPatterns);
    printf("| State Density    : %.1f%%\n", 100.0*(double)mbom->mbomNumTrans/(mbom->mbomSize * ALPHABET_SIZE));
    printf("| All MBOMs' Memory: %.2fKbytes\n", (float)max_memory/1024 );
    printf("+---------------------------------------------------------------------------------\n\n");
    printf("+------------------ AHO-CORASICK STATE MACHINE INFO FOLLOWS: ---------------------\n\n");
    
    acsmPrintDetailInfo(mbom->acsm);
}

/*
 *   Global sumary of all mbom info and all state machines built during this run
 */
void mbomPrintSummaryInfo2()
{
  // this IF is for mpsePrintSummary (which doesn't check which method is in use)
  if(summary.num_states > 0) { 
    printf("+--[Pattern Matcher:Multi Backward Oracle Matching (MultiBOM) Overall Summary]----\n");
    printf("| Alphabet Size    : %u Chars\n",ALPHABET_SIZE);
    printf("| Size of State    : %u bytes\n",(int)(sizeof(MBOM_STATE)));
    printf("| Num States       : %u\n",summary.num_states);
    printf("| Num Transitions  : %u\n",summary.num_transitions);
    printf("| Num Groups       : %u\n",summary.num_groups);
    printf("| Num Patterns     : %u\n",summary.num_patterns);
    printf("| State Density    : %.1f%%\n", 100.0*(double)summary.num_transitions / (summary.num_states * ALPHABET_SIZE));
    printf("| Memory Usage     : %.2fKbytes\n", (float)max_memory/1024 );
    printf("+---------------------------------------------------------------------------------\n\n");
    printf("+----------------- AHO-CORASICK STATE MACHINE SUMMARY FOLLOWS: -------------------\n\n");
    
    acsmPrintSummaryInfo();
  }
}



//#define MBOM2_MAIN

#ifdef MBOM2_MAIN

#include <time.h>

/*
*  Text Data Buffer
*/ 
unsigned char text[2048];

/* 
*    A Match is found
*/ 
int MatchFound (void* id, int index, void *data) 
{
  printf("MATCH:%s\n", (char *) id);
  return 0;
}

/*
* MAIN (for testing purposes)
*/ 
int main (int argc, char **argv) 
{
  int i, nc, nocase = 0;
  MBOM_STRUCT2 * mbom;
  char * p;
  clock_t start, stop;

  if (argc < 3) {
    fprintf (stderr,"\nUsage: %s search-text pattern +pattern... [flags]\n",argv[0]);
    fprintf (stderr,"  flags: -nocase -verbose\n");
    fprintf (stderr,"  use a + in front of pattern for single case insensitive pattern\n\n");
    exit (0);
  }

  mbom = mbomNew2();
  
  if(!mbom) {
    printf("mbom-no memory\n");
    exit(0);
  }
  
  if(s_verbose) {
    printf("Parsing Parameters...\n");
  }

  strcpy (text, argv[1]);

  for(i = 1; i < argc; ++i) {
  
    if(strcmp(argv[i], "-nocase") == 0) {
      nocase = 1;
    }
    if(strcmp (argv[i], "-verbose") == 0) {
      s_verbose = MBOM_VERBOSE;
    }
  }

  for (i = 2; i < argc; ++i) {
      if (argv[i][0] == '-') /* a switch */
        continue;

      p = argv[i];

      if ( *p == '+') {
          nc=1;
          ++p;
      }
      else {
          nc = nocase;
      }

      mbomAddPattern2(mbom, p, strlen(p), nc, 0, 0, (void*)p, i - 2);
  }
  
  if(s_verbose) printf("Patterns added\n");

  start = clock();
  mbomCompile2(mbom);
  stop = clock();

  if(s_verbose) {
     printf("Patterns compiled in (%f seconds)\n", ((double)(stop-start))/CLOCKS_PER_SEC);
     mbomPrintDetailInfo2(mbom);
     printf("\n");
     mbomPrintSummaryInfo2();
     printf("\nSearching text...\n");
  }
  
  start = clock();
  mbomSearch2(mbom, text, strlen(text), MatchFound, (void *)0 );
  stop = clock();
  
  if(s_verbose) printf ("Done search in (%f seconds)\n", ((double)(stop-start))/CLOCKS_PER_SEC);
  
  mbomFree2(mbom);

  if(s_verbose) printf ("Done cleaning\n");

  return 0;
}

#endif /* include main program */

