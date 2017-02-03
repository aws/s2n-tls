Require Import List.

Parameter string : Type.

Parameter empty_string : string.

Parameter concat : string -> string -> string.

(*3 axioms about concatenation that should hold for any reasonable implementation *)
Axiom concat_assoc : forall a b c, concat a (concat b c) = concat (concat a b) c. 
Axiom concat_empty : forall s : string, concat s empty_string = s.
Axiom concat_empty_l : forall s : string, concat empty_string s = s.


Parameter state : Type.

Parameter HMAC : string -> string -> string.

Parameter HMAC_init : string -> state.

Parameter HMAC_update : string -> state -> state.

Parameter HMAC_digest : state -> string.

(* We have proved this as stated here in SAW *)
Axiom update_concat : forall m1 m2 s,
    HMAC_update (concat m1 m2) s = HMAC_update m2 (HMAC_update m1 s).

(* We have proved this for a set of m and k sizes in SAW *)
Axiom equiv_one : forall m k,
    HMAC_digest (HMAC_update m (HMAC_init k)) = HMAC k m.

(* Not yet proved in SAW, can be proved as stated *)
Axiom update_empty : forall s, HMAC_update empty_string s = s.

Lemma fold_right_concat : forall s l,
    fold_right concat (s) l = concat (fold_right concat empty_string l) s.
Proof.
  induction l.
  simpl in *. rewrite concat_empty_l. auto.
  simpl in *. rewrite IHl. rewrite concat_assoc. auto.
Qed.

Lemma update_concat_any:
  forall (l : list string) (key s : string),
    HMAC_update (concat (fold_right concat empty_string (rev l)) s) (HMAC_init key) =
    HMAC_update s (fold_right HMAC_update (HMAC_init key) l).
Proof.
  induction l; intros.
    + simpl in *. rewrite concat_empty_l. auto.
    + simpl in *. rewrite <- update_concat. rewrite fold_right_app.
      simpl. rewrite fold_right_concat. simpl. rewrite concat_empty. rewrite <- IHl. f_equal.
      rewrite concat_assoc. auto.
Qed.
  
Theorem HMAC_incremental_equiv :
  forall (ms : list string) key,
    HMAC key (fold_right concat empty_string ms) =
    HMAC_digest (fold_left (fun (st: state) msg => HMAC_update msg st) ms (HMAC_init key)).
Proof.
  intros.
  rewrite <- fold_left_rev_right in *.
  remember (rev ms).
  destruct l; simpl.
  - rewrite <- equiv_one. destruct ms.
    + simpl. rewrite update_empty. auto.
    +  assert (rev nil = rev (rev (s :: ms))). f_equal. auto.
       clear Heql. rewrite rev_involutive in *. simpl in *. congruence.
  - rewrite <- equiv_one. rewrite <- update_concat_any.
    f_equal.  assert (rev (s :: l) = rev (rev ms)). f_equal. auto.
    rewrite rev_involutive in *. subst. clear Heql. simpl.
    rewrite fold_right_app. simpl. rewrite concat_empty. rewrite fold_right_concat. auto.
Qed.