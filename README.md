# snort-ids-multi-pattern-matching
Snort 2.6 with added implementation of backwards oracle multi-pattern matching algorithm

This is the accompaniment to James Kelly's (my) MCS thesis (see thesis.pdf). For further details about this thesis code and what it does please consult the thesis paper.

I'm grateful for the interest I've had in this project over the last decade since I wrote this code, but I can not longer support this, so please help yourself, but support is also DIY.

#####After cloning:
(replace $installdir$ with desired directory location):
```
cd snort
sh autojunk.sh
./configure --prefix=$installdir/snort2.6.0
make
make install
```
Adding the rules and test Snort configuration files:

Extract the contents of add2bin.tar.gz to the $installdir$/snort2.6.0/bin directory

(As root possibly) do a: 'mkdir /var/log/snort' and if was root then just 'chmod 777 /var/log/snort' or else run snort tests as root

For testing configure (edit) the simpletest.sh and test.sh with the appropriate directory locations.



### My code

Most of my new data structure and algorithm code is is sfutil/mbom.* 

### Notes from sftul/mbom2.c

*Multi-Pattern Search Engine*

MultiBOM - or Multi Backwards Oracle Matching

Version 2.0

Reference: (Original MultiBOM proposal) - IN FRENCH
C. Allauzen and M. Raffinot. Oracle des facteurs d'un ensemble de mots.
Technical Report IGM 99-11, Institut Gaspard Monge, Universite de 
Marne-la-Vallee, France, 1999.

Reference: (BEST REFERENCE FOR SBOM and how to build a factor oracle)
G. Navarro and M. Raffinot. Flexible Pattern Matching in Strings, 
Practical On-line Search Algorithms for Texts and Biological Sequences.
Cambridge University Press, Cambridge, UK, 2002

Reference: (BEST REFERENCE FOR MultiBDM)
M. Crochemore and W. Rytter. Text Algorithms. Oxford University Press, 1994.
Pages 140-143 *Example in book has a mistake in it; one pattern is not matched*

Reference:
M. Raffinot. On the multi backward DAWG matching algorithm (MultiBDM). In
R. Baeza-Yates, editor, WSP'97: Proceedings of the 4th South American Work-
shop on String Processing, pages 149{165, Valparaiso, Chile, Nov. 1997. 
Carleton University Press.

*Version 1.0 Notes - James Kelly:*

1) Finds all occurrences of all patterns within a text.

2) Currently supports only the use of a factor oracle; however, MultiDAWG 
   uses the same approach with a DAWG (Directed Acyclic Word Graph)
 
3) MBOM is an implementation of MultiBOM from first reference. It
   is for use in Snort and uses Snort's standard version of its
   Aho-Corasick state machine (acsmx.h/c).

4) MBOM doesn't take much extra memory compared to Snort's standard
   Aho-Corasick state machine pattern matcher; however, the running time
   will greatly be *enhanced* (faster) because MBOM is average case
   and worst case optimal. That is, it's sublinear (wrt text length)
   on average and linear (wrt text length) in the worst case. The
   average case is defined as only indepedent equiprobable characters
   appearing in the search text. The MBOM algorithm executes at most
   2n inspections of search text characters where the search text
   length is n.

5) MBOM uses a window size of length equal to the minimum length
   pattern. Therefore, shifts are limited by this window size.
   Thus, it is not/hardly worth using the MBOM algorithm unless
   the minimum length pattern is at least of length 3. Note that
   for those cases the Aho-Corasick algorithm would be faster.

*New Version 2.0 Notes - James Kelly:*

1) This version uses a hashtable and there is no trie or nodes. It is
   all virtual in the hashtable which of course saves a lot (tons) of
   memory. For comparison for the Snort default rule DB MBOM v1.0 
   would take 14331.21 KB of memory + 157366.49 KB for the Aho-Corasick
   State Machine - ACSM), but MBOM v2.0 takes 548.70Kbytes + the same 
   for the ACSM. In the memory usage of the factor oracle there's a 
   difference of 26:1 (ratio)!

2) Still only supports only the use of a factor oracle; however, MultiDAWG 
   uses the same approach with a DAWG (Directed Acyclic Word Graph).
 
3) States in the factor oracle are represented by a uint16_t therefore we
   are limited to 2^16 states. That should be plenty considering the factor 
   oracle's depth is cut off at the length of the shortest pattern. It should
   be easy to change it to a uint32_t if needed, but of course this will 
   increase memory cost per state as well.

4) The hashtable holds a state id and character as a key, and another state 
   id as the value. The character is the label on the transition between the
   two states.

5) MBOM v1.0 stored the supply state in the NODE which meant it was kept around
   after pre-computation, but it actually isn't needed. In this version the
   memory to hold the supply function (supply states) is only allocated during
   precomputation (the compile routine). Before the search phase it is deleted.
