Require Import List.
Import ListNotations.
Require Import String.

(* Borrow from CompCert *)
Require Import Coqlib.
Require Import Bitvectors.

Require Import AST.
Require Import Semantics.
Require Import Utils.
Require Import Builtins.
Require Import BuiltinSem.
Require Import BuiltinSyntax.
Require Import Values.        
Require Import Eager.
Require Import Bitstream.

Require Import EvalTac.

Import HaskellListNotations.
Open Scope string.

Require Import HMAC.

Require Import HMAC_spec.

Require Import HMAC_lib.

Require Import Kinit_eval.


(* lemma for when the length of the key is the same as the length of the block *)
Lemma Hmac_eval_keylen_is_blocklength :
  forall (key : ext_val) keylen,
    has_type key (bytestream keylen) -> 
    forall GE TE SE, 
      wf_env ge GE TE SE ->
      (forall id, In id [(371, "ks");(372, "okey");(373, "ikey");(374, "internal")] -> GE id = None) ->
      forall h hf,
        good_hash h GE TE SE hf ->
        forall msg msglen unused,
          has_type msg (bytestream msglen) ->
          exists v,
            eager_eval_expr GE TE SE (apply (tapply (EVar hmac) ((typenum (Z.of_nat msglen)) :: (typenum (Z.of_nat keylen)) :: (typenum unused) :: (typenum (Z.of_nat keylen)) :: nil)) (h :: h :: h :: (EValue (to_val key)) :: (EValue (to_val msg)) :: nil)) (to_sval v) /\ hmac_model hf key msg = Some v.
Proof.
  intros.
  rename H1 into HIDs.
  rename H2 into H1.
  rename H3 into H2.
  init_globals ge.
  abstract_globals ge.
  edestruct good_hash_complete_eval; eauto.
  do 4 destruct H3.

  inversion H. subst.
  inversion H2. subst.
  remember (hf (eseq (map (fun x3 : ext_val => xor_const 54 x3) l ++ l0))) as hv1.
  assert (HT : exists n, has_type hv1 (tseq n tbit)). {
    assert (exists n, has_type (eseq (map (fun x3 : ext_val => xor_const 54 x3) l ++ l0)) (bytestream n)). {
      eexists. econstructor.
      rewrite Forall_app. split.
      eapply Forall_map. eauto.
      intros. eapply xor_const_byte; eauto.
      eauto.
    }
    destruct H5.
    eapply H4 in H5. destruct H5. subst hv1. eauto.
  }
  destruct HT as [n0'].
  rename H5 into HT.
  edestruct ext_val_list_of_strictval; try eassumption.
  rename H5 into Hlres.
  
  
  eexists; split.

  e. e. e. e. e. e. e. e. e.
  ag.

  e. e. e. e. e.
  eassumption.
  e. eassumption.
  e. eassumption.
  e. e.

  eapply strict_eval_val_to_val.

  e. e.
  eapply strict_eval_val_to_val.

  e. e. e. e. e. e. e. e.
  g. simpl. unfold extend. simpl.
  eapply wf_env_not_local; eauto.
  reflexivity.

  e.
  e. e. e.
  eapply eager_eval_global_var.
  reflexivity.
  reflexivity.
  e. e. e. eapply eager_eval_global_var.
  reflexivity.
  reflexivity.

  
  eapply kinit_eval.

  unfold bind_decl_groups.
  unfold erase_decl_groups.

  repeat eapply wf_env_extend_TE.
  repeat eapply wf_env_erase_SE.
  repeat eapply wf_env_extend_SE.
  repeat eapply wf_env_extend_GE.
  eassumption.

  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.
  reflexivity.

  exact H.


  eapply good_hash_same_eval; eauto.
  e. 

  repeat e. repeat e.
  repeat e. e.
  
  simpl.
  rewrite list_of_strictval_of_strictlist. 
  reflexivity.
  
  (* Begin model section *)
  eapply eager_eval_bind_senvs. eassumption.
  instantiate (1 := fun x => to_sval (xor_const 92 x)).  
  intros. e. e. e. g. unfold extend. simpl.
  eapply wf_env_not_local; eauto. reflexivity.
  e. e. e. e. e. e. g.
  unfold extend. simpl.
  eapply wf_env_not_local; eauto. reflexivity.
  e. repeat e. repeat e. e. repeat e.
  repeat e. simpl.
  inversion H5. subst. simpl.
  unfold strictnum.
  unfold Z.to_nat. unfold Pos.to_nat.
  unfold Pos.iter_op. unfold Init.Nat.add.
  rewrite <- H6.
  rewrite xor_num. reflexivity.
  rewrite H6. eassumption.
  reflexivity.
  (* End model section *)

  e. g.
  e. e. e. e. g.
  simpl. unfold extend. simpl. eapply wf_env_not_local; eauto.
  reflexivity.
  e. e. e. e. e. e. e. e. e. e. e. g.
  simpl. unfold extend. simpl. eapply wf_env_not_local; eauto.
  reflexivity.
  e. e. e. e. g.
  e. e. e. g.
  eapply kinit_eval.

  unfold bind_decl_groups.
  unfold erase_decl_groups.
  repeat eapply wf_env_extend_GE.
  repeat eapply wf_env_extend_TE.
  repeat eapply wf_env_erase_SE.
  repeat eapply wf_env_extend_SE.
  assumption.

  all: try solve [reflexivity].

  exact H.
  
  solve [eapply good_hash_same_eval; eauto; e].

  repeat e.
  repeat e. repeat e. e.

  simpl.
  rewrite list_of_strictval_of_strictlist. 
  reflexivity.


  eapply eager_eval_bind_senvs. eassumption.
  instantiate (1 := fun x => to_sval (xor_const 54 x)).  
  intros. e. e. e. g. unfold extend. simpl.
  eapply wf_env_not_local; eauto. reflexivity.
  e. e. e. e. e. e. g.
  unfold extend. simpl.
  eapply wf_env_not_local; eauto. reflexivity.
  e. repeat e. repeat e. e. repeat e.
  repeat e. simpl.
  inversion H5. subst. simpl.
  unfold strictnum.
  unfold Z.to_nat. unfold Pos.to_nat.
  unfold Pos.iter_op. unfold Init.Nat.add.
  rewrite <- H6.
  rewrite xor_num. reflexivity.
  rewrite H6. eassumption.
  reflexivity.

  e. e. e. repeat e.
  repeat e.
  
  unfold to_sval. fold to_sval.
  rewrite append_strict_list. 
  reflexivity.

  eapply global_extends_eager_eval.

  replace (map (fun x3 : ext_val => to_sval (xor_const 54 x3)) l) with
      (map to_sval (map (fun x3 => xor_const 54 x3) l)) by (rewrite list_map_compose; reflexivity).
  rewrite <- list_append_map.
  remember (app (map (fun x3 : ext_val => xor_const 54 x3) l) l0) as ll.
  replace (strict_list (map to_sval ll)) with (to_sval (eseq ll)) by (reflexivity).
  subst ll.
  eapply H4.
  econstructor.

  rewrite Forall_app. split; auto.
  eapply Forall_map. eassumption.

  intros. eapply xor_const_byte; eauto.

  unfold bind_decl_groups.
  unfold bind_decl_group.
  unfold declare.
  
  repeat (eapply global_extends_extend_r; try eapply wf_env_name_irrel_GE; eauto).
  eapply global_extends_refl.

  eapply HIDs. simpl. left. reflexivity.
  eapply HIDs. simpl. right. left. reflexivity.
  eapply HIDs. simpl. right. right. left. reflexivity.
  eapply HIDs. simpl. right. right. right. left. reflexivity.
  
  e. repeat e.
  e. e. e.

  simpl.
  rewrite <- Heqhv1.
  rewrite Hlres. reflexivity.
  
  e. repeat e. repeat e.

  rewrite append_strict_list. reflexivity.
  eapply global_extends_eager_eval.

  (* get to_sval out to outside *)
  (* evaluate the hash function *)

  replace (map (fun x4 : ext_val => to_sval (xor_const 92 x4)) l) with
  (map to_sval (map (xor_const 92) l)) by
      (clear -l; 
       induction l; simpl; auto; f_equal; eapply IHl; eauto).
    
  rewrite get_each_n_map_commutes.


  rewrite map_strict_list_map_map_to_sval.
  rewrite <- list_append_map.
  rewrite strict_list_map_to_sval.

  (* This one will be some fun *)
  assert (exists n, has_type (eseq (map (xor_const 92) l ++ map eseq (get_each_n (Pos.to_nat 8) x3))) (bytestream n)). {


    eapply has_type_seq_append.
    exists (Datatypes.length (map (xor_const 92) l)).
    econstructor.
    eapply Forall_map. eassumption.
    intros. eapply xor_const_byte; eauto.
    subst hv1.
    inversion HT. subst.
    rewrite <- H5 in Hlres.
    eapply list_of_strictval_to_sval in Hlres. inversion Hlres.
    subst. clear Hlres.
    remember H1 as HHash.
    clear HeqHHash.
    symmetry in H5.
    eapply good_hash_fully_padded in H1; try eassumption.
    eapply type_stream_of_bytes in H1; eauto.
  }
  
  destruct H5.
  eapply H4 in H5. destruct H5. eapply H5.

  repeat (eapply global_extends_extend_r; try eapply wf_env_name_irrel_GE; eauto).
  eapply global_extends_refl.

  eapply HIDs. simpl. left. reflexivity.
  eapply HIDs. simpl. right. left. reflexivity.
  eapply HIDs. simpl. right. right. left. reflexivity.
  eapply HIDs. simpl. right. right. right. left. reflexivity.

  (* our result matches the model *)
  subst hv1.
  eapply list_of_strictval_to_sval in Hlres.
  simpl. rewrite Hlres.

  reflexivity.

  Unshelve.
  all: exact id.
  
Qed.
