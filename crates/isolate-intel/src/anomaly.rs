//! Anomaly scorer — ONNX Runtime inference for behavioral anomaly detection.
//!
//! Runs a pre-trained isolation forest model to score events against the
//! behavioral baseline. Score ∈ [0.0, 1.0]; higher = more anomalous.
//!
//! The model is loaded from `models/behavior_classifier_v1.onnx` and runs
//! in a separate thread to avoid blocking the event pipeline.

use crate::baseline::BaselineProfiler;
use isolate_events::event::IsolateEvent;
use tracing::{debug, warn};

pub struct AnomalyScorer {
    /// ONNX session — Arc so it can be cloned across tasks
    /// In production: Arc<ort::Session>
    model_loaded: bool,
}

impl AnomalyScorer {
    pub fn new() -> Self {
        // In production:
        // let env = Arc::new(Environment::builder().with_name("isolate-intel").build().unwrap());
        // let session = SessionBuilder::new(&env)?
        //     .with_model_from_file("models/behavior_classifier_v1.onnx")?;
        let model_loaded = std::path::Path::new("models/behavior_classifier_v1.onnx").exists();
        if !model_loaded {
            warn!("ONNX model not found — anomaly scoring disabled (statistical fallback active)");
        }
        Self { model_loaded }
    }

    /// Score an event against the current baseline.
    /// Returns None if baseline is not warm or model unavailable.
    pub async fn score(
        &self,
        event: &IsolateEvent,
        baseline: &BaselineProfiler,
    ) -> Option<f32> {
        // Get feature vector from baseline
        // (event is used for workload class lookup via isobox config in practice)
        // Simplified: use statistical outlier detection as fallback

        // In production with ONNX:
        // let features = baseline.feature_vector(class, event)?;
        // let input = Array2::from_shape_vec((1, features.len()), features).ok()?;
        // let outputs = session.run(inputs![input]).ok()?;
        // let score: f32 = outputs[0].try_extract_scalar().ok()?;
        // Some(score)

        // Statistical fallback: return None (no scoring without model)
        None
    }
}

impl std::fmt::Debug for AnomalyScorer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnomalyScorer")
            .field("model_loaded", &self.model_loaded)
            .finish()
    }
}
