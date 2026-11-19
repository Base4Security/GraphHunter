//! Rarity of a process is scored per image, not per instance.
//!
//! A process id names one execution on one host
//! (`process_identity::process_id`). Scored by its own degree or its own
//! observation count, each of the many `cmd.exe` executions is as "rare"
//! as the single run of an attacker's tool, and the ranking stops telling
//! them apart — measured on `scripts/eval/`: three benign `cmd.exe`
//! instances entered the top-10 anomalies.

use graph_hunter_core::process_identity::{ProcessRef, process_id};
use graph_hunter_core::{Entity, EntityType, GraphHunter, Relation, RelationType};

const CMD: &str = "C:\\Windows\\System32\\cmd.exe";
const TOOL: &str = "C:\\Users\\Public\\credtool.exe";
const COMMON_RUNS: usize = 60;

fn instance(host: &str, n: usize, image: &str) -> String {
    let guid = format!("{{{n:08x}}}");
    process_id(&ProcessRef {
        host: Some(host),
        image,
        guid: Some(&guid),
        pid: None,
    })
}

/// `COMMON_RUNS` executions of cmd.exe spread over hosts and one execution
/// of an unusual tool; every execution is started once by some user.
fn graph(scoring: bool) -> (GraphHunter, String, String) {
    let mut g = GraphHunter::new();
    if scoring {
        g.enable_anomaly_scoring(Default::default());
    }
    let add = |g: &mut GraphHunter, user: String, proc_id: &str, ts: i64| {
        g.add_entity(Entity::new(user.clone(), EntityType::User))
            .ok();
        g.add_entity(Entity::new(proc_id, EntityType::Process)).ok();
        g.add_relation(Relation::new(
            user,
            proc_id.to_string(),
            RelationType::Execute,
            ts,
        ))
        .unwrap();
    };
    let mut one_cmd = String::new();
    for n in 0..COMMON_RUNS {
        one_cmd = instance(&format!("ws-{}", n % 7), n, CMD);
        add(
            &mut g,
            format!("user-{n}"),
            &one_cmd,
            1_700_000_000 + n as i64,
        );
    }
    let tool = instance("ws-3", 9_999, TOOL);
    add(&mut g, "user-3".to_string(), &tool, 1_700_000_500);
    g.sort_edges_by_timestamp().unwrap();
    (g, one_cmd, tool)
}

#[test]
fn structural_rarity_ranks_the_unusual_image_above_a_common_one() {
    let (mut g, one_cmd, tool) = graph(false);
    g.compute_scores();
    let rarity = |id: &str| {
        g.get_entity(id)
            .unwrap_or_else(|| panic!("node {id}"))
            .rarity_score
    };
    // Each instance has exactly one edge; only the image tells them apart.
    assert!(
        rarity(&tool) > rarity(&one_cmd) + 20.0,
        "tool {} vs cmd.exe instance {}",
        rarity(&tool),
        rarity(&one_cmd)
    );
}

#[test]
fn anomaly_estimate_ranks_the_unusual_image_above_a_common_one() {
    let (mut g, one_cmd, tool) = graph(true);
    g.finalize_anomaly_scorer();
    let scorer = g.anomaly_scorer.as_ref().expect("scorer enabled");
    let (tool_score, cmd_score) = (
        scorer.node_anomaly_estimate(&tool),
        scorer.node_anomaly_estimate(&one_cmd),
    );
    assert!(
        tool_score > cmd_score,
        "tool {tool_score} must outrank a cmd.exe instance {cmd_score}"
    );
}
