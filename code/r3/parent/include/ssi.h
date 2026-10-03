/*
 * SSI Verification Kernel — executable reference for
 *   Specification I : Safe Super Intelligence: Definition, Architecture, and Verification Standard v1.0
 *   Specification II: Safe Super Intelligence Axiomatic System v1.0
 * by Michael Aaron Russell. PURE WAD¹⁸: integer-only, fail-closed.
 */
#ifndef SSI_H
#define SSI_H

#include <stdint.h>
#include <stddef.h>
#include "wad18.h"

/* ---------- three-valued results (Axiom S2; Standard §14) ---------- */
typedef enum { SSI_TT = 0, SSI_FF = 1, SSI_UNKNOWN = 2 } ssi_truth;
typedef enum { VER_PASS = 0, VER_FAIL = 1, VER_UNKNOWN = 2 } ver_result;

/* VS(X): at least one declared invariant (S1) and every invariant TT (S2). */
int ssi_vs(const ssi_truth *inv, size_t n);

/* ---------- Axiomatic System: membership (Def. 21, §33) ---------- */
int ssi_member(int si, int vs, int hg, int auth_state, int ver_state);
int ssi_member_prov(int si, int vs, int hg, int auth_state, int ver_state, int prov);

/* ---------- Axiomatic System: execution gate (Def. 11, Axiom A2, §31) ---------- */
typedef enum { GATE_REJECT = 0, GATE_COMMIT = 1 } gate_outcome;
int ssi_permit4(int auth, int safe_action, int ver, int cap);
gate_outcome ssi_execute(int auth, int safe_action, int ver, int cap, int invariant_next);

/* ---------- CSL authorization (Axiom C1) ---------- */
int ssi_csl_auth(int signature_valid, int revoked, uint64_t valid_until, uint64_t now, int in_envelope);

/* ---------- Standard: Permit predicate (§13) ---------- */
typedef struct {
    int type_ok, action_well_typed, csl_valid, authorized, capability_valid, safety_inv,
        action_safe, evidence_valid, deployment_bound, current, revoked, within_scope, fresh;
} permit13;
int ssi_permit13(const permit13 *c);
int ssi_permit13_from_bits(uint32_t bits);   /* bit i = condition i in declaration order */

/* ---------- Standard: decision (§7, §13, §14, §23) ---------- */
typedef enum { DEC_EXECUTE = 0, DEC_REJECT = 1, DEC_DEFER = 2, DEC_SAFE_STOP = 3 } decision;
decision ssi_decide(int arithmetic_valid, ver_result v, int permit);
const char *decision_name(decision d);

/* ---------- Standard: action typing and mediation (§8, §9) ---------- */
typedef enum { ACT_NONE = -1, ACT_READ, ACT_COMPUTE, ACT_COMMUNICATE, ACT_WRITE, ACT_PURCHASE,
               ACT_DEPLOY, ACT_CREDENTIAL, ACT_PHYSICAL, ACT_SELF_MODIFY, ACT_POLICY_CHANGE } action_type;
int ssi_mediate(action_type kind, int permit);   /* 1 = external effect emitted */

/* ---------- Standard: directives (§10) ---------- */
int ssi_directive_valid(int signature_valid, uint64_t issue, uint64_t expiry, uint64_t revocation_epoch,
                        uint64_t now, uint64_t current_epoch, int in_scope);

/* ---------- Standard: capability non-escalation (§17), deployment binding (§16) ---------- */
int ssi_capability_ok(uint32_t next_caps, uint32_t authorized_caps, int governance_approved);
int ssi_certifies(int cert_valid, const char *cert_deployment, const char *deployment);

/* ---------- R³ adoption (Axiomatic Def. 23; Standard §18) ---------- */
int ssi_adopt4(int kernel_equal, int proof_valid, int authorization_valid, int non_regression);
int ssi_adopt6(int kernel_equal, int safety_proof_valid, int authorization_valid,
               int deployment_certificate_valid, int non_regression, int capability_disclosure_valid);
/* Def. 24: every invariant true before stays true after. */
int ssi_non_regression(const ssi_truth *before, const ssi_truth *after, size_t n);

/* ---------- Safety Asset Class ---------- */
/* Axiomatic Def. 27 + §28: certified now iff SSI ∧ VALID(C) ∧ VALID(P) ∧ BOUND ∧ AUTHENTIC ∧ ¬REVOKED */
int ssi_sac_current(int ssi, int cert_valid, int prov_valid, int bound, int authentic, int revoked);
/* Standard §21–§22 */
typedef enum { ST_PROPOSED, ST_VERIFIED, ST_ACTIVE, ST_REVALIDATION, ST_REVOKED, ST_REJECTED } asset_status;
int ssi_can_transition(asset_status from, asset_status to);
int ssi_sac_active(int ssi, int prov_valid, int scope_valid, int fresh, asset_status status);
const char *status_name(asset_status s);

/* ---------- Minimal verification kernel VERIFY_SSI (Axiomatic §31) ---------- */
typedef struct {
    int type_valid, wad18_valid, kernel_valid, csl_valid, authorization_valid,
        safety_invariants_valid, capability_valid, certificate_valid, certificate_binds,
        provenance_valid, superintelligence_criterion;
} ssi_verify_input;
/* Returns NULL on PASS, or the name of the first failed check (checks run in §31 order). */
const char *ssi_verify(const ssi_verify_input *x);

/* ---------- Canonical encoding and identity (Axiomatic §29) ---------- */
typedef struct { const char *key; const char *value; } kv;
/* ENC(X): keys sorted, "key=value\n" lines; returns bytes written (truncated output is an error: -1). */
int ssi_encode(const kv *fields, size_t n, char *out, size_t cap);
/* ID_X = SHA-256(ENC(X)) as hex. Returns 0 on success. */
int ssi_state_id(const kv *fields, size_t n, char hex[65]);

#endif
