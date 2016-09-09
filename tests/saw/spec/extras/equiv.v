Require Import List.

Parameter string : Type.

Parameter empty_string : string.

Parameter concat : string -> string -> string.

Axiom concat_assoc : forall a b c, concat a (concat b c) = concat (concat a b) c. 

Axiom concat_empty : forall s : string, concat s empty_string = s.
Axiom concat_empty_l : forall s : string, concat empty_string s = s.


Parameter state : Type.

Parameter HMAC : string -> string -> string.

Parameter HMAC_init : string -> state.

Parameter HMAC_update : string -> state -> state.

Parameter HMAC_digest : state -> string.

Axiom update_concat : forall m1 m2 s,
    HMAC_update (concat m1 m2) s = HMAC_update m2 (HMAC_update m1 s).

Axiom equiv_one : forall m k,
    HMAC_digest (HMAC_update m (HMAC_init k)) = HMAC k m.

Axiom update_empty : forall s, HMAC_update empty_string s = s.

Lemma fold_right_concat : forall s l,
        fold_right concat (s) l = concat (fold_right concat empty_string l) s.
Proof.
      induction l.
      simpl in *. rewrite concat_empty_l. auto.
      simpl in *. rewrite IHl. rewrite concat_assoc. auto.
      Qed.



Theorem HMAC_incremental_equiv :
  forall (ms : list string) key,
    HMAC key (fold_right concat empty_string ms) =
    HMAC_digest (fold_left (fun (st: state) msg => HMAC_update msg st) ms (HMAC_init key)).
Proof.
  intros.
  rewrite <- fold_left_rev_right in *.
  remember (length ms).
  generalize dependent ms.
  revert key.
  induction n; intros.
  - intros. destruct ms.
    + simpl in *. rewrite <- equiv_one.  rewrite update_empty. auto.
    + simpl in *. congruence.
  - intros. assert (S n = length (rev ms)).  rewrite rev_length. apply Heqn.
    destruct (rev ms) eqn:?; simpl in *; try congruence. assert ((rev (rev ms)) = rev (s :: l)) by congruence.
    rewrite rev_involutive in *. simpl in *. subst. rewrite fold_right_app. simpl in *.
    rewrite fold_right_concat. rewrite <- equiv_one. simpl in *. f_equal. clear - n.
    revert s. clear n.
    induction l; intros.
    + simpl in *. rewrite concat_empty_l. rewrite concat_empty. auto.
    + simpl in *. rewrite <- update_concat. rewrite concat_empty in *. rewrite fold_right_app.
      simpl. rewrite fold_right_concat. simpl. rewrite concat_empty. rewrite <- IHl. f_equal.
      rewrite concat_assoc. rewrite concat_empty. rewrite concat_assoc. auto.
Qed.
  