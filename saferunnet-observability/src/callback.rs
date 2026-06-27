use parking_lot::Mutex;
use std::fmt::Write;
use std::sync::Arc;
use tracing::Subscriber;
use tracing_subscriber::layer::Context;
use tracing_subscriber::Layer;

/// Callback function type for log consumption.
/// Lokinet C++ equivalent: lokinet_logger_func
pub type LogCallback = Arc<dyn Fn(&str) + Send + Sync>;

/// A tracing Layer that forwards formatted log events to a callback.
/// Lokinet C++ equivalent: CallbackSink (spdlog::sinks::base_sink)
pub struct CallbackLayer {
    callback: LogCallback,
    ringbuf: Option<Arc<super::ringbuf::LogRingBuffer>>,
    target: Mutex<String>,
}

impl CallbackLayer {
    pub fn new(callback: LogCallback) -> Self {
        Self {
            callback,
            ringbuf: None,
            target: Mutex::new(String::new()),
        }
    }

    pub fn with_ringbuf(
        callback: LogCallback,
        ringbuf: Arc<super::ringbuf::LogRingBuffer>,
    ) -> Self {
        Self {
            callback,
            ringbuf: Some(ringbuf),
            target: Mutex::new(String::new()),
        }
    }
}

impl<S: Subscriber> Layer<S> for CallbackLayer {
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let mut target = self.target.lock();
        target.clear();

        // Format: [LEVEL] target: message {key=value}
        let metadata = event.metadata();
        let _ = write!(target, "[{}] {}: ", metadata.level(), metadata.target());

        let mut visitor = StringVisitor(&mut *target);
        event.record(&mut visitor);

        // Push to ring buffer if configured
        if let Some(ref ringbuf) = self.ringbuf {
            ringbuf.push(target.clone());
        }

        // Forward to callback
        (self.callback)(target.as_str());
    }
}

struct StringVisitor<'a>(&'a mut String);

impl tracing::field::Visit for StringVisitor<'_> {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.0, "{:?}", value);
        } else {
            let _ = write!(self.0, " {}={:?}", field.name(), value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tracing_subscriber::layer::SubscriberExt;

    #[test]
    fn test_callback_layer_constructible() {
        let collected = Arc::new(Mutex::new(Vec::new()));
        let collected_clone = collected.clone();
        let callback: LogCallback = Arc::new(move |msg: &str| {
            collected_clone.lock().push(msg.to_string());
        });

        let layer = CallbackLayer::new(callback);
        let _subscriber = tracing_subscriber::registry().with(layer);
    }
}
