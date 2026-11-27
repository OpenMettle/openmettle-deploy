//! Kind-only V1-31 restore-drill fixture seeding a parked human-approval `waiting` run and a
//! revision-zero two-phase external write `intent` via pinned `openmettle-core` store APIs.
//! Reads `<api_url>\n<worker_url>\n<session_cookie>\n` from stdin so zero credentials appear in argv.
use openmettle_core::{
    authz::{
        CapabilityGate,
        approvals::{
            Destination, EffectClass, EffectPolicy, EndpointKey, Proposal, Review, park,
        },
        leases::LeaseSettings,
        runs::{Admission, AdmissionLimits, ClaimLimits, RunAdmission, admit_run_with_mode, claim_next},
        store::StoreError,
    },
    runs::{Intent, Payload, RunInput, WriteTransaction, record_intent},
    sessions,
    worker::StepTasks,
};
use serde_json::json;
use sqlx::{Connection, PgConnection};
use std::{io, time::Duration};

struct DrillEffectPolicy;

impl EffectPolicy for DrillEffectPolicy {
    fn review(&self, _: &str, _: &str, p: &Proposal) -> Result<Option<Review>, StoreError> {
        if p.tool != "drill.mail"
            || p.version != "1"
            || p.destination() != r#"["v1","drill","inbox","send","external"]"#
        {
            return Ok(None);
        }
        Ok(Some(Review {
            class: EffectClass::HumanRequired,
            capability: "tool.mail".into(),
            gate: CapabilityGate::OnByDefault,
            tool_policy: "drill-1".into(),
            destination_policy: "dest-drill-1".into(),
            endpoint_id: "drill.inbox".into(),
            endpoint_version: "mail-1".into(),
            endpoint_key: EndpointKey::Supported {
                namespace: "drill".into(),
                field: "Idempotency-Key".into(),
                valid_from_us: 1,
                key: format!("drill-effect-{}", p.logical_key),
                expires_us: 4_102_444_800_000_000,
            },
            authoritative_lookup: true,
            artifact: None,
            reservation: None,
        }))
    }
}

fn proposal(logical_key: &str) -> Proposal {
    Proposal::new(
        logical_key,
        "drill.mail",
        "1",
        br#"{"subject":"synthetic restore drill approval"}"#,
        Destination {
            connection: "drill",
            account: "inbox",
            action: "send",
            resource: "external",
        },
    )
    .expect("valid synthetic proposal")
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [actor, approval] = args.as_slice() else {
        panic!("usage: drill-fixture <actor_user_id> <actor_approval_id>");
    };
    let mut lines = io::stdin().lines();
    let api_url = lines.next().expect("api url line").expect("api url");
    let worker_url = lines.next().expect("worker url line").expect("worker url");
    let cookie = lines.next().expect("session cookie line").expect("cookie");

    let mut api_conn = PgConnection::connect(api_url.trim())
        .await
        .expect("api connection");
    let mut worker_conn = PgConnection::connect(worker_url.trim())
        .await
        .expect("worker connection");

    let session_policy =
        sessions::Policy::new(Duration::from_secs(28_800), 16, Duration::from_secs(5)).unwrap();
    let effect_session = openmettle_core::authz::approvals::EffectSession::validate(
        &mut api_conn,
        cookie.trim(),
        &session_policy,
        None,
    )
    .await
    .expect("valid seeded session");

    let scope: String = sqlx::query_scalar(
        "SELECT id::text FROM openmettle.scopes WHERE personal_user_id = $1::uuid",
    )
    .bind(actor)
    .fetch_one(&mut api_conn)
    .await
    .expect("personal scope");

    let limits = AdmissionLimits {
        live_per_actor: 8,
        live_per_scope: 16,
        queued_in_instance: 32,
        round_cap: 4,
        queue_timeout: Duration::from_secs(600),
    };
    let claim_limits = ClaimLimits {
        executing_per_actor: 4,
        executing_per_scope: 8,
    };
    let lease_settings = LeaseSettings {
        lease_duration: Duration::from_secs(60),
        execution_timeout: Duration::from_secs(300),
        db_timeout: Duration::from_secs(2),
    };

    // Helper: create conversation + branch + message + admit + claim + park in `waiting`.
    let mut created_waiting = Vec::new();
    for (idx, idem_key, prop_key) in [
        (1, "drill-waiting-approval-run", "approval-gate-1"),
        (2, "drill-waiting-intent-run", "approval-gate-2"),
    ] {
        let conv: String = sqlx::query_scalar(
            "INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id)
             VALUES ($1::uuid, 'personal', $2::uuid) RETURNING id::text",
        )
        .bind(&scope)
        .bind(actor)
        .fetch_one(&mut api_conn)
        .await
        .unwrap();
        let branch: String = sqlx::query_scalar(
            "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
             VALUES ($1::uuid, $2::uuid) RETURNING id::text",
        )
        .bind(&scope)
        .bind(&conv)
        .fetch_one(&mut api_conn)
        .await
        .unwrap();
        let msg: String = sqlx::query_scalar(
            "INSERT INTO openmettle.messages (scope_id, conversation_id)
             VALUES ($1::uuid, $2::uuid) RETURNING id::text",
        )
        .bind(&scope)
        .bind(&conv)
        .fetch_one(&mut api_conn)
        .await
        .unwrap();

        let config_bytes = json!({"execution_mode": "ordinary"}).to_string();
        let now_ms: i64 = sqlx::query_scalar(
            "SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint",
        )
        .fetch_one(&mut api_conn)
        .await
        .unwrap();
        let req = RunAdmission {
            input: RunInput {
                scope: &scope,
                actor,
                conversation: &conv,
                branch: &branch,
                message: &msg,
                key: idem_key,
                format: "openmettle.drill-synthetic",
                version: 1,
                input: format!("{{\"step\":{idx}}}").as_bytes(),
                config: config_bytes.as_bytes(),
            },
            actor_approval_id: approval,
            capabilities: &[],
            requested_rounds: None,
            now_ms,
            cost_qualified: None,
        };
        let mut tx = WriteTransaction::begin(&mut api_conn).await.unwrap();
        let Admission::Admitted { run_id, .. } =
            admit_run_with_mode(&mut tx, &req, &limits, &effect_session)
                .await
                .expect("admit drill run")
        else {
            panic!("expected new admission for {idem_key}");
        };
        tx.commit().await.unwrap();

        let claimed = claim_next(&mut worker_conn, &claim_limits, &lease_settings)
            .await
            .expect("claim_next")
            .expect("claimed drill run");
        assert_eq!(claimed.run_id, run_id, "claimed unexpected run");

        let parked = park(
            &mut worker_conn,
            &claimed.lease(),
            &StepTasks::default().handle(),
            &proposal(prop_key),
            &DrillEffectPolicy,
            &lease_settings,
            Duration::from_secs(7200),
        )
        .await
        .expect("park run for approval");
        created_waiting.push((run_id, parked.approval_id, parked.binding_digest));
    }

    // Record a revision-0 non_repeatable write intent on the second waiting run so pre-worker
    // restore cancellation proves `openmettle.resolve_terminal_write_intents()` transitions it
    // to `outcome_unknown` (revision 1) without dispatching any external effect.
    let intent_run_id = &created_waiting[1].0;
    let mut wtx = WriteTransaction::begin(&mut worker_conn).await.unwrap();
    let operation_id = record_intent(
        &mut wtx,
        &Intent {
            scope: &scope,
            run: intent_run_id,
            key: "external-write-effect-1",
            target: "https://mcp.example.test/tools/send",
            capability: "non_repeatable",
            request: Payload {
                format: "openmettle.mcp-write-intent",
                version: 1,
                bytes: br#"{"tool":"drill.send","idempotent":false}"#,
            },
        },
    )
    .await
    .expect("record non_repeatable write intent");
    wtx.commit().await.unwrap();

    println!(
        "{}",
        json!({
            "scope_id": scope,
            "waiting_run_id": created_waiting[0].0,
            "waiting_approval_id": created_waiting[0].1,
            "waiting_binding_digest": created_waiting[0].2,
            "intent_run_id": created_waiting[1].0,
            "intent_operation_id": operation_id,
        })
    );
}
