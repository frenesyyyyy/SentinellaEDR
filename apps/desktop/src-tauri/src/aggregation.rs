//! Display batching for non-alert telemetry.

use std::collections::HashMap;
use tokio::sync::Mutex;

/// Process event payload serializable to JSON.
#[derive(serde::Serialize, Clone, Debug)]
pub struct ProcessEvent {
    pub timestamp: String,
    pub pid: u32,
    pub process: String,
    pub event_type: String,
    pub details: String,
    pub enforcement: String,
    /// Number of aggregated duplicate events (None or 1 = single event)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(process: &str, event_type: &str, pid: u32) -> ProcessEvent {
        ProcessEvent {
            timestamp: format!("12:00:{pid:02}"),
            pid,
            process: process.into(),
            event_type: event_type.into(),
            details: format!("event-{pid}"),
            enforcement: "Observed".into(),
            count: None,
        }
    }

    #[tokio::test]
    async fn single_event_omits_count_and_flush_drains_buffer() {
        let aggregator = EventAggregator::new();
        aggregator.insert(event("browser", "Process Exec", 1)).await;
        let batch = aggregator.flush().await;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].count, None);
        assert!(serde_json::to_value(&batch[0])
            .unwrap()
            .get("count")
            .is_none());
        assert!(aggregator.flush().await.is_empty());
    }

    #[tokio::test]
    async fn duplicates_keep_latest_payload_even_when_pid_and_details_differ() {
        let aggregator = EventAggregator::new();
        aggregator.insert(event("browser", "Process Exec", 1)).await;
        aggregator.insert(event("browser", "Process Exec", 2)).await;
        let batch = aggregator.flush().await;
        assert_eq!(batch.len(), 1);
        assert_eq!(batch[0].count, Some(2));
        assert_eq!(batch[0].pid, 2);
        assert_eq!(batch[0].details, "event-2");
        assert_eq!(batch[0].timestamp, "12:00:02");
    }

    #[tokio::test]
    async fn different_processes_and_event_types_remain_separate() {
        let aggregator = EventAggregator::new();
        aggregator.insert(event("browser", "Process Exec", 1)).await;
        aggregator
            .insert(event("browser", "Network Connect", 2))
            .await;
        aggregator.insert(event("editor", "Process Exec", 3)).await;
        let batch = aggregator.flush().await;
        assert_eq!(batch.len(), 3);
        assert!(batch.iter().all(|event| event.count.is_none()));
    }
}

// Group display events by process and type; the latest event represents each group.
pub(crate) const AGGREGATION_WINDOW_MS: u64 = 250;

/// Key used to group duplicate events in the aggregation window.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
struct AggKey {
    process: String,
    event_type: String,
}

/// Buffered state for a single aggregation key.
#[derive(Clone, Debug)]
struct AggBucket {
    /// The most recent event for this key (used as the representative).
    representative: ProcessEvent,
    /// How many raw events have been collapsed into this bucket.
    count: u32,
}

/// Thread-safe event aggregator shared between the ring-buffer reader and the
/// periodic flush task.
pub(crate) struct EventAggregator {
    buffer: Mutex<HashMap<AggKey, AggBucket>>,
}

impl EventAggregator {
    pub(crate) fn new() -> Self {
        Self {
            buffer: Mutex::new(HashMap::new()),
        }
    }

    /// Insert a benign event into the aggregation buffer.
    pub(crate) async fn insert(&self, event: ProcessEvent) {
        let key = AggKey {
            process: event.process.clone(),
            event_type: event.event_type.clone(),
        };
        let mut buf = self.buffer.lock().await;
        let entry = buf.entry(key).or_insert_with(|| AggBucket {
            representative: event.clone(),
            count: 0,
        });
        entry.count += 1;
        // Always keep the latest timestamp/pid as the representative
        entry.representative = event;
    }

    /// Drain the buffer and return all aggregated events ready for emission.
    pub(crate) async fn flush(&self) -> Vec<ProcessEvent> {
        let mut buf = self.buffer.lock().await;
        let drained: Vec<ProcessEvent> = buf
            .drain()
            .map(|(_, bucket)| {
                let mut ev = bucket.representative;
                ev.count = if bucket.count > 1 {
                    Some(bucket.count)
                } else {
                    None
                };
                ev
            })
            .collect();
        drained
    }
}
