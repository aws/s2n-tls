#include <smack.h>
#include "ct-verif.h"
#include "../sidewinder.h"

#define MAX_LEAKAGE_DIFFERENCE  68

int nondet();

int s2n_verify_cbc(struct s2n_connection *conn, struct s2n_hmac_state *hmac, struct s2n_blob *decrypted)
{
  int leakage = nondet();
  //We have a proof that the max leakage this step can introduce is MAX_LEAKAGE_DIFFERENCE
  __VERIFIER_assume(leakage >= 0);
  __VERIFIER_assume(leakage < MAX_LEAKAGE_DIFFERENCE);
  __VERIFIER_ASSUME_LEAKAGE(leakage);
  return 0;
}
