#ifndef CT_VERIF_H
#define CT_VERIF_H

#ifndef COMPILE
#include <smack.h>

/*
Security levels are the following.

For inputs:
- public - function requires (assumes) these to be equal.
- private - no requirement (allowed to vary freely)

For outputs (both by reference and return values):
- public - function ensures these are equal
           can be used on left-hand side of implications everywhere
- private - no guarantee (allowed to vary freely)
- declassified - we only analyse executions in which these
                 possibly private values are fixed.

We omit annotations for private since nothing needs to be generated
 for them. We may need to add them back in for modular analyses.
*/

/* The abstract prototypes that form our annotation language */
void public_in(smack_value_t);
void public_out(smack_value_t);
void declassified_out(smack_value_t);
void public_invariant(smack_value_t);
void benign(void);

#define __disjoint_regions(addr1,len1,addr2,len2) \
  assume(addr1 + len1 * sizeof(*addr1) < addr2 || \
         addr2 + len2 * sizeof(*addr2) < addr1)

#else /* COMPILE */

#undef __SMACK_value

#define __VERIFIER_assume(__a)
#define __SMACK_value(__a)
#define __SMACK_return_value(__a)
#define __SMACK_values(__a,__b)
#define __SMACK_return_values(__a)

#define public_in(__a)
#define public_out(__a)
#define declassified_out(__a)
#define public_invariant(__a)

#define __disjoint_regions(addr1,len1,addr2,len2)

#endif /* COMPILE */
#endif /* CT_VERIF_H */
