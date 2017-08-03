(* This file has been taken from https://github.com/PrincetonUniversity/VST/blob/master/hmacfcf/HMAC_spec.v *)
(* It has been formatted to fit your repository *)

(* Copyright 2012-2015 by Adam Petcher.				*
 * Use of this source code is governed by the license described	*
 * in the LICENSE file at the root of the source tree.		*)
Set Implicit Arguments.


Require Import Bvector.
Require Import List.
Require Import Arith.

Definition Blist := list bool.

Fixpoint splitVector(A : Set)(n m : nat) : Vector.t A (n + m) -> (Vector.t A n * Vector.t A m) :=
  match n with
    | 0 =>
      fun (v : Vector.t A (O + m)) => (@Vector.nil A, v)
    | S n' =>
      fun (v : Vector.t A (S n' + m)) =>
        let (v1, v2) := splitVector _ _ (Vector.tl v) in
          (Vector.cons _ (Vector.hd v) _ v1, v2)
  end.

Section HMAC.

  Variable c p : nat.
  Definition b := c + p.

  (* The compression function *)
  Variable h : Bvector c -> Bvector b -> Bvector c.
  (* The initialization vector is part of the spec of the hash function. *)
  Variable iv : Bvector c.
  (* The iteration of the compression function gives a keyed hash function on lists of words. *)
  Definition h_star k (m : list (Bvector b)) :=
    fold_left h m k.
  (* The composition of the keyed hash function with the IV gives a hash function on lists of words. *)
  Definition hash_words := h_star iv.

  Variable Message : Set.
  Variable splitAndPad : Message -> list (Bvector b).
  Hypothesis splitAndPad_1_1 :
    forall b1 b2,
      splitAndPad b1 = splitAndPad b2 ->
      b1 = b2.

  Variable fpad : Bvector c -> Bvector p.
  Definition app_fpad (x : Bvector c) : Bvector b :=
    (Vector.append x (fpad x)).

  Definition h_star_pad k x :=
    app_fpad (h_star k x).

  Definition GNMAC k m :=
    let (k_Out, k_In) := splitVector c c k in
    h k_Out (app_fpad (h_star k_In m)).

  (* The "two-key" version of GHMAC and HMAC. *)
  Definition GHMAC_2K (k : Bvector (b + b)) m :=
    let (k_Out, k_In) := splitVector b b k in
      let h_in := (hash_words (k_In :: m)) in
        hash_words (k_Out :: (app_fpad h_in) :: nil).

  Definition HMAC_2K (k : Bvector (b + b)) (m : Message) :=
    GHMAC_2K k (splitAndPad m).

  (* opad and ipad are constants defined in the HMAC spec. *)
  Variable opad ipad : Bvector b.
  Hypothesis opad_ne_ipad : opad <> ipad.

  Definition GHMAC (k : Bvector b) :=
    GHMAC_2K (Vector.append (BVxor _ k opad) (BVxor _ k ipad)).

  Definition HMAC (k : Bvector b) :=
    HMAC_2K (Vector.append (BVxor _ k opad) (BVxor _ k ipad)).

End HMAC.