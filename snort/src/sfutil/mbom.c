/*
**   $Id$
** 
**   mbom.c
**
**   Multi-Pattern Search Engine
**
**   MultiBOM - or Multi Backwards Oracle Matching
**
**   Version 1.0
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
**      (and worst case) optimal. That is, it's sublinear (wrt text length)
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
**
*/  
  
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>


#include "mbom.h"

//#define DEBUG_MBOM
  
/*
* facilitates: memory checks
*/ 
#define MEMASSERT(p,s) if(!p){printf("MBOM-No Memory: %s!\n",s);exit(0);}

/*
* Keep this for stats:
*/ 
static int max_memory = 0;

/*
* toggle verbose for all instances of MBOM
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

}mbom_summary_t;

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
  MBOM_NODE * node; //data
  uint8_t     character; //data
  MBOM_NODE * parent; //data
  struct _qnode *next;
}
QNODE;

/*
*    Simple QUEUE Structure
*/ 
typedef struct _queue
{
  QNODE * head, *tail;
  int count;
}
QUEUE;

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
static void queue_add (QUEUE * s, MBOM_NODE * node, MBOM_NODE * parent, uint8_t character)
{
  QNODE * q;

  if (!s->head)
  {
      // don't count this in summary it will be deleted (it's tmp only)
      // a queue is never kept during the search only used for 
      // precomputation/preprocessing purposes.
      q = s->tail = s->head = (QNODE *) malloc (sizeof (QNODE));
      MEMASSERT (q, "queue_add");
      q->node      = node;
      q->parent    = parent;
      q->character = character;
      q->next = NULL;
  }
  else
  {
      q = (QNODE *) malloc (sizeof (QNODE)); //don't count this in summary
      q->node      = node;
      q->parent    = parent;
      q->character = character;
      q->next = NULL;
      s->tail->next = q;
      s->tail = q;
  }
  s->count++;
}


/*
*  Remove Head Item from queue
*/ 
static void queue_remove (QUEUE * s, MBOM_NODE ** node, MBOM_NODE ** parent, uint8_t * character) 
{
  void * data;
  QNODE * q;
  
  data = NULL;
  
  if (s->head)
  {
      q       = s->head;
      *node      = q->node;
      *parent    = q->parent;
      *character = q->character;
      s->head = s->head->next;
      s->count--;

      if( !s->head )
      {
	  s->tail = NULL;
	  s->count = 0;
      }
      free (q);
  }
}

/*
*   Return items in the queue
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

/*
* measure memory allocations
*/ 
static void * MBOM_MALLOC (uint32_t size)
{
  void * p;
  p = malloc (size);
  if (p) {
    max_memory += size;
  }
  return p;
}

/*
* measure memory deallocations
*/
static void MBOM_FREE (void * p, uint32_t size) 
{
  if (p) {
    free (p);
    max_memory -= size;
  }
}

/*
* toggle between verbose mode on/off with 1/0
*/ 
void mbomSetVerbose(int n)
{
  s_verbose = n;
}

/*
*   Select the desired storage mode
*/
int mbomSelectFormat(MBOM_STRUCT * mbom, int format)
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
MBOM_STRUCT * mbomNew() 
{
  MBOM_STRUCT * p;

  init_xlatcase();

  p = (MBOM_STRUCT *) MBOM_MALLOC(sizeof (MBOM_STRUCT));
  MEMASSERT (p, "mbomNew");
  memset (p, 0, sizeof (MBOM_STRUCT));
  
  p->acsm = acsmNew();
  MEMASSERT (p->acsm, "mbomNew (acsm)");

  ++(summary.num_groups);
  
  return p;
}

/*
*   Add a pattern to the list of patterns for this instance
*/ 
int mbomAddPattern(MBOM_STRUCT * mbom, unsigned char * pat, int n, int nocase,
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

#ifdef DEBUG_MBOM
/*
*   Prints out the factor oracle structure:
*
*   This prints out the F.O. the same way as v2.0
*   for comparison purposes (they should be the same)
*/
static void printMbom(MBOM_STRUCT * mbom)
{
  QUEUE q;
  int j;
  MBOM_NODE * current, * parent;
  uint8_t currentCharacter;
  
  printf("\nMBOM structure:\n");
  
  /* use queue to facilitate a breadth first traversal over the node/states
   * of the trie to print them */
  queue_init(&q);
  
  for(j = 0; j < ALPHABET_SIZE; ++j) {
    if(mbom->initialState->next_states[j] != NULL) {
      // enqueue the node itself, its parent, and the character between them on the transition
      queue_add(&q, mbom->initialState->next_states[j], mbom->initialState, j);
      printf("t(%d,%x) = %d\n", mbom->initialState->id, j, mbom->initialState->next_states[j]->id);
    }
  }
  
  while(queue_count(&q)) {

    queue_remove(&q, &current, &parent, &currentCharacter);

    /* Enqueue all children nodes of current */
    for(j = 0; j < ALPHABET_SIZE; ++j) {
      if(current->next_states[j] != NULL) {
        // enqueue the node itself, its parent, and the character between them on the transition
        queue_add(&q, current->next_states[j], current, j);
	printf("t(%d,%x) = %d\n", current->id, j, current->next_states[j]->id);
      }
    }
  }

  queue_free(&q);
  printf("\n");
}
#endif

/*
* Helper used by the function below it (mbomCompile)
*/
static MBOM_NODE * newMbomState()
{
  MBOM_NODE * node;
  
  node = (MBOM_NODE *) MBOM_MALLOC(sizeof(MBOM_NODE));
  MEMASSERT (node, "newMbomState");
  memset(node, 0, sizeof(MBOM_NODE)); // zero values are defaults and all pointers are NULL

  return node;
}

/*
 * Helper fnc used by mbomCompile
 * Sets a bit to 1 in the table
 */
static void setBit(uint8_t * bitTable, uint8_t index)
{
  uint8_t j = 0;
  uint8_t bitPos = index % 8; // is the place of the bit to set in the (index/8)th byte
  uint8_t bitMask = 1;
  
  for(j = 0; j < bitPos; ++j) { 
    bitMask <<= 1;
  }
  
  bitTable[index / 8] |= bitMask; // set bit
}

/*
 * Helper fnc used by deleteMbomNode and in turn mbomFree
 * Returns 1 if bit is set to 1 in table otherwise 0
 */
static uint8_t getBit(uint8_t * bitTable, uint8_t index)
{
  uint8_t j = 0;
  uint8_t bitPos = index % 8; // is the place of the bit to set in the (index/8)th byte
  uint8_t bitMask = 1;
  
  for(j = 0; j < bitPos; ++j) {
    bitMask <<= 1;
  }
    
  if((bitTable[index / 8] & bitMask) == 0) { // get bit
    return 0;
  }
  return 1;
}

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
int mbomCompile(MBOM_STRUCT * mbom)
{  
  int              j;
  ACSM_PATTERN     * plist;
  MBOM_NODE        * current, * new, * parent;
  uint8_t          currentCharacter;
  QUEUE            q; // temp for Breadth-First Traversal
  
  /* Create Trie: */
  /* ------------ */
  
  mbom->initialState = newMbomState();  // Initial State
  ++(mbom->mbomSize);
  mbom->initialState->id = mbom->mbomSize;
  
  for (plist = mbom->acsm->acsmPatterns; plist != NULL; plist = plist->next) {
    current = mbom->initialState;
    j = plist->n - 1; //start at the end of the patttern because we're entering it reversed
    
    while(j >= 0 && current->next_states[plist->patrn[j]] != NULL) {
      current = current->next_states[plist->patrn[j]];
      --j;
    }
    
    while(j >= 0) {
      current = (current->next_states[plist->patrn[j]] = newMbomState());
      --j;
      ++(mbom->mbomNumTrans);  // Add Transition
      ++(mbom->mbomSize); // Add State
      current->id = mbom->mbomSize;
    }
  }

  
  /* Build Factor Oracle From Trie: */
  /* ------------------------------ */
  
  /* We need to create external transitions with a breadth first traversal */
  
  // use queue to facilitate a breadth first traversal over the node/states
  // of the trie to make the factor oracle
  queue_init(&q);
  
  for(j = 0; j < ALPHABET_SIZE; ++j) {
    if(mbom->initialState->next_states[j] != NULL) {
      // enqueue the node itself, its parent, and the character between them on the transition
      queue_add(&q, mbom->initialState->next_states[j], mbom->initialState, j);
    }
  }
  
  while(queue_count(&q)) {

    queue_remove(&q, &current, &parent, &currentCharacter);

    /* Process current node */
    // new moves ("up") towards the root/initialState
    
    new = parent->supply_state;

    while(new != NULL && new->next_states[currentCharacter] == NULL) {
    
      // Add an external transition
      new->next_states[currentCharacter] = current;
      ++(mbom->mbomNumTrans); // Add Transition

      // set bit in bit table to indicate this is an extended transition
      setBit(new->extendedTransitions, currentCharacter);
      
      new = new->supply_state;
    }

    if(new != NULL) {
      current->supply_state = new->next_states[currentCharacter];
    }
    else {
      current->supply_state = mbom->initialState;
    }

    /* Enqueue all children nodes of current */
    for(j = 0; j < ALPHABET_SIZE; ++j) {
      if(current->next_states[j] != NULL) {
        // enqueue the node itself, its parent, and the character between them on the transition
        queue_add(&q, current->next_states[j], current, j);
      }
    }
  }
  
  queue_free(&q);
  
  /* Tell the ACSM to compile itself too */
  /* ----------------------------------- */
  acsmCompile(mbom->acsm);
  
  /* Accrue Summary State Stats */
  summary.num_states      += mbom->mbomSize;
  summary.num_transitions += mbom->mbomNumTrans;

#ifdef DEBUG_MBOM
  printMbom(mbom);
  mbomPrintDetailInfo(mbom);
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
int mbomSearch(MBOM_STRUCT * mbom, unsigned char *Tx, int n,
           int (*Match) (void * id, int index, void *data), 
           void *data)
{
  int nfound     = 0; /* num of patterns found */
  int min        = mbom->minLen; // minimal length of patterns (also the window size)
  int i          = 0; // i is the position of the window on the text
  int critpos    = 0; // position of the input head of the ACSM
  int j          = 0; // tmp (may go to -1 tmply)
  int end        = n - min + 1; // last valid i + 1
  int windowEnd  = min - 1;
  MBOM_NODE * current = NULL;
  
  int state           = 0; /* ACSM current state*/
  ACSM_PATTERN        * mlist; /* tmp list of patterns at a terminal state */
  ACSM_STATETABLE     * states = mbom->acsm->acsmStateTable;
  
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
    
    j = i + windowEnd; // last char in window
    current = mbom->initialState;
    
    // Search for factor mismatch in the oracle/dawg:
    
    while(j >= critpos && (current = current->next_states[Tc[j]]) != NULL) {
        --j;
    }

    if(j >= critpos) { //if it didn't make it all the way to the critpos
      state = 0; // reset ACSM
      critpos = j + 1;
    }

    // Search with ACSM between indexes critpos "up to" n-1:
    
    while(critpos < n && (critpos < i + min || states[state].depth >= min)) {
      
      state = states[state].NextState[Tc[critpos]]; // scan one character
      ++critpos;
      
      if(states[state].MatchList != NULL) { // if this state is terminal
      
        /* Go through the patterns that match at this state */

        for(mlist=states[state].MatchList; mlist != NULL; mlist = mlist->next) {

          /* j = location that match starts in Tx */
          j = critpos - (uint16_t)mlist->n;
          
          /* obviously faster for patterns that are case insensitive */
          if(mlist->nocase) {
            ++nfound; ++(mbom->matches);
            if(Match (mlist->id, j, data))
              return nfound;
          }
          else {
            if(memcmp(mlist->casepatrn, Tx + j, mlist->n) == 0) {
              ++nfound; ++(mbom->matches);
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
 * Helper fnc used by mbomFree
 * Free node (recursive helper)
 */
static void deleteMbomNode(MBOM_NODE * node)
{
  int j;
  
  if(node == NULL) {
    return;
  }
  
  /* delete all children */
  for(j = 0; j < ALPHABET_SIZE; ++j) {
    // check that it is not an extended transition
    // if it is then it "belongs" to another MBOM_NODE
    if(node->next_states[j] != NULL && (getBit(node->extendedTransitions, j) == 0)) {
      deleteMbomNode(node->next_states[j]);
    }
  }
  
  /* delete node */
  MBOM_FREE(node, sizeof (MBOM_NODE));
}

/*
*   Free all memory
*/ 
void mbomFree(MBOM_STRUCT * mbom) 
{
  deleteMbomNode(mbom->initialState); // deletes all states and transitions
  
  acsmFree(mbom->acsm); // deletes the ACSM
  
  MBOM_FREE(mbom, sizeof (MBOM_STRUCT));
  
  --(summary.num_groups);
}

static int ins_num = 0;


/*
*   Prints information about a mbom matcher instance
*/
void mbomPrintDetailInfo(MBOM_STRUCT * mbom)
{
    char * sf[]= {"Factor Oracle", "DAWG (Directed Acyclic Word Graph)"};
    
    printf("+--[Pattern Matcher:Multi Backward Oracle Matching (MultiBOM) Instance Info]------\n");
    printf("| Instance Number  : %u\n", ++ins_num);
    printf("| Alphabet Size    : %u Chars\n", ALPHABET_SIZE);
    printf("| Size of State    : %u bytes\n", (int)(sizeof(MBOM_NODE)));
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
void mbomPrintSummaryInfo()
{
  // this IF is for mpsePrintSummary (which doesn't check which method is in use)
  if(summary.num_states > 0) { 
    printf("+--[Pattern Matcher:Multi Backward Oracle Matching (MultiBOM) Overall Summary]----\n");
    printf("| Alphabet Size    : %u Chars\n",ALPHABET_SIZE);
    printf("| Size of State    : %u bytes\n",(int)(sizeof(MBOM_NODE)));
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



//#define MBOM_MAIN

#ifdef MBOM_MAIN

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
  MBOM_STRUCT * mbom;
  char * p;
  clock_t start, stop;

  if (argc < 3) {
    fprintf (stderr,"\nUsage: %s search-text pattern +pattern... [flags]\n",argv[0]);
    fprintf (stderr,"  flags: -nocase -verbose\n");
    fprintf (stderr,"  use a + in front of pattern for single case insensitive pattern\n\n");
    exit (0);
  }

  mbom = mbomNew();
  
  if(!mbom) {
    printf("mbom-no memory\n");
    fflush(stdout);
    exit(0);
  }
  
  if(s_verbose) {
    printf("Parsing Parameters...\n");
    fflush(stdout);
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

      mbomAddPattern(mbom, p, strlen(p), nc, 0, 0, (void*)p, i - 2);
  }
  
  if(s_verbose) { printf("Patterns added\n"); fflush(stdout); }

  start = clock();
  mbomCompile(mbom);
  stop = clock();

  if(s_verbose) {
     printf("Patterns compiled in (%f seconds)\n", ((double)(stop-start))/CLOCKS_PER_SEC);
     fflush(stdout);
     mbomPrintDetailInfo(mbom);
     printf("\n");
     mbomPrintSummaryInfo();
     printf("\nSearching text...\n");
     fflush(stdout);
  }
  
  start = clock();
  mbomSearch(mbom, text, strlen(text), MatchFound, (void *)0 );
  stop = clock();
  
  if(s_verbose) printf ("Done search in (%f seconds)\n", ((double)(stop-start))/CLOCKS_PER_SEC);
  
  mbomFree(mbom);

  if(s_verbose) printf ("Done cleaning\n");

  return 0;
}
#endif /* include main program */

