//! Kind-only caller of the pinned core's store until V1-07 exposes HTTP admission.
use openmettle_core::{
    authz::runs::{Admission, AdmissionLimits, RunAdmission, admit_run},
    runs::{RunInput, WriteTransaction},
};
use sqlx::{Connection, PgConnection};
use std::{io, time::Duration};

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let args: Vec<_> = std::env::args().skip(1).collect();
    let [actor, approval, key, timeout] = args.as_slice() else {
        panic!("expected actor, approval, admission key and queue timeout in seconds");
    };
    let mut url = String::new();
    io::stdin().read_line(&mut url).unwrap();
    let mut conn = PgConnection::connect(url.trim())
        .await
        .expect("fixture database");
    let (scope, now_ms): (String, i64) = sqlx::query_as(
        "SELECT id::text, (extract(epoch FROM clock_timestamp()) * 1000)::bigint
         FROM openmettle.scopes WHERE personal_user_id = $1::uuid AND current_user = 'openmettle_api'",
    ).bind(actor).fetch_one(&mut conn).await.unwrap();
    let conversation: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversations (scope_id, scope_kind, owner_user_id)
         VALUES ($1::uuid, 'personal', $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(actor)
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let branch: String = sqlx::query_scalar(
        "INSERT INTO openmettle.conversation_branches (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&conversation)
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let message: String = sqlx::query_scalar(
        "INSERT INTO openmettle.messages (scope_id, conversation_id)
         VALUES ($1::uuid, $2::uuid) RETURNING id::text",
    )
    .bind(&scope)
    .bind(&conversation)
    .fetch_one(&mut conn)
    .await
    .unwrap();
    let request = RunAdmission {
        input: RunInput {
            scope: &scope,
            actor,
            conversation: &conversation,
            branch: &branch,
            message: &message,
            key,
            format: "openmettle.synthetic-run",
            version: 1,
            input: b"{}",
            config: b"{}",
        },
        actor_approval_id: approval,
        capabilities: &[],
        requested_rounds: None,
        now_ms,
        // No catalog profile: the low-level caller form (core ADR 0040).
        cost_qualified: None,
    };
    let limits = AdmissionLimits {
        live_per_actor: 1,
        live_per_scope: 1,
        queued_in_instance: 1,
        round_cap: 1,
        queue_timeout: Duration::from_secs(timeout.parse().unwrap()),
    };
    let mut tx = WriteTransaction::begin(&mut conn).await.unwrap();
    let Admission::Admitted { run_id, .. } = admit_run(&mut tx, &request, &limits).await.unwrap()
    else {
        panic!("expected a new admission");
    };
    tx.commit().await.unwrap();

    let mut retry = WriteTransaction::begin(&mut conn).await.unwrap();
    let Admission::Replayed {
        run_id: original,
        state,
        ..
    } = admit_run(&mut retry, &request, &limits).await.unwrap()
    else {
        panic!("expected an idempotent replay");
    };
    assert!(original == run_id && state == "queued");
    retry.rollback().await.unwrap();
    println!("{run_id}");
}
