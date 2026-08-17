//! The `fi.refineid.stream.v1` transport profile of specification
//! Section 16.1.
//!
//! The requester runs the listener; the proxy dials exactly once, at
//! pairing. That single accepted connection then lives as the session for
//! the pairing's whole life, so the plaintext preamble that opens every
//! connection has one registered purpose: reaching the listener's active
//! pairing offer. The preamble is unauthenticated routing metadata; it
//! enables nothing but that selection, and every anomaly closes the
//! connection without touching any state (Section 14.5, class 1).

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::cbor::Value;
use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};

/// Domain string opening every stream preamble.
const STREAM_PREAMBLE_DOMAIN: &str = "RAPP-stream-v1";

/// The preamble's only registered purpose: the active pairing offer.
const PURPOSE_PAIRING: &str = "pairing";

/// Upper bound on an encoded preamble frame; the listener rejects a longer
/// preamble before parsing it.
pub const MAX_STREAM_PREAMBLE_FRAME: usize = 64;

/// Candidate parameter key carrying the listener endpoint list.
const PARAMETER_ENDPOINTS: &str = "endpoints";

/// Maximum listener endpoints one stream candidate may carry.
pub const MAX_STREAM_ENDPOINTS: usize = 8;

/// Maximum UTF-8 bytes of one `host:port` endpoint literal.
pub const MAX_STREAM_ENDPOINT_BYTES: usize = 255;

/// The plaintext connection preamble, the first frame the dialing proxy
/// sends on a fresh stream connection before any Noise message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StreamPreamble;

impl StreamPreamble {
    /// Encodes the preamble frame payload.
    ///
    /// # Errors
    ///
    /// Fails only when the value cannot be encoded within the wire limits.
    pub fn encode(self) -> Result<Vec<u8>, StreamError> {
        Value::Array(vec![
            Value::Text(STREAM_PREAMBLE_DOMAIN.to_owned()),
            Value::Text(PURPOSE_PAIRING.to_owned()),
        ])
        .encode()
        .map_err(|_| StreamError::Malformed)
    }

    /// Decodes and validates one received preamble frame payload.
    ///
    /// # Errors
    ///
    /// Every failure is pre-authentication invalid input: the caller closes
    /// the connection and changes no state. The retired `session` purpose is
    /// an unregistered purpose like any other.
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STREAM_PREAMBLE_FRAME {
            return Err(StreamError::Oversized);
        }
        let Ok(Value::Array(elements)) = Value::decode(bytes) else {
            return Err(StreamError::Malformed);
        };
        let [Value::Text(domain), Value::Text(purpose)] = elements.as_slice() else {
            return Err(StreamError::Malformed);
        };
        if domain != STREAM_PREAMBLE_DOMAIN {
            return Err(StreamError::Malformed);
        }
        if purpose != PURPOSE_PAIRING {
            return Err(StreamError::UnknownPurpose);
        }
        Ok(Self)
    }
}

/// Builds the stream candidate `parameters` entries for a pairing offer.
///
/// # Errors
///
/// Fails on an empty list, more than [`MAX_STREAM_ENDPOINTS`] entries, or
/// an endpoint literal that is empty or exceeds
/// [`MAX_STREAM_ENDPOINT_BYTES`].
pub fn stream_candidate_parameters(
    endpoints: &[String],
) -> Result<Vec<(String, Value)>, StreamError> {
    validate_endpoints(endpoints)?;
    Ok(vec![(
        PARAMETER_ENDPOINTS.to_owned(),
        Value::Array(
            endpoints
                .iter()
                .map(|endpoint| Value::Text(endpoint.clone()))
                .collect(),
        ),
    )])
}

/// Reads the listener endpoints back out of offer candidate parameters.
///
/// # Errors
///
/// Fails when the parameters are not exactly the registered stream shape.
pub fn stream_candidate_endpoints(
    parameters: &[(String, Value)],
) -> Result<Vec<String>, StreamError> {
    let [(key, Value::Array(elements))] = parameters else {
        return Err(StreamError::Malformed);
    };
    if key != PARAMETER_ENDPOINTS {
        return Err(StreamError::Malformed);
    }
    let endpoints = elements
        .iter()
        .map(|element| match element {
            Value::Text(endpoint) => Ok(endpoint.clone()),
            _ => Err(StreamError::Malformed),
        })
        .collect::<Result<Vec<_>, _>>()?;
    validate_endpoints(&endpoints)?;
    Ok(endpoints)
}

fn validate_endpoints(endpoints: &[String]) -> Result<(), StreamError> {
    if endpoints.is_empty() || endpoints.len() > MAX_STREAM_ENDPOINTS {
        return Err(StreamError::EndpointCount);
    }
    if endpoints
        .iter()
        .any(|endpoint| endpoint.is_empty() || endpoint.len() > MAX_STREAM_ENDPOINT_BYTES)
    {
        return Err(StreamError::EndpointLength);
    }
    Ok(())
}

/// The requester's stream listener.
#[derive(Debug)]
pub struct StreamListener {
    listener: TcpListener,
    candidate_id: String,
    receive_deadline: Duration,
}

impl StreamListener {
    /// Binds the listener.
    ///
    /// # Errors
    ///
    /// Fails when the address cannot be bound.
    pub fn bind(
        address: &str,
        candidate_id: &str,
        receive_deadline: Duration,
    ) -> Result<Self, StreamError> {
        let listener = TcpListener::bind(address).map_err(|_| StreamError::Bind)?;
        Ok(Self {
            listener,
            candidate_id: candidate_id.to_owned(),
            receive_deadline,
        })
    }

    /// The bound local port, for assembling advertised endpoints.
    ///
    /// # Errors
    ///
    /// Fails when the socket cannot report its address.
    pub fn local_port(&self) -> Result<u16, StreamError> {
        self.listener
            .local_addr()
            .map(|address| address.port())
            .map_err(|_| StreamError::Bind)
    }

    /// Accepts one connection, reads exactly one bounded preamble frame,
    /// and validates it, returning the connection positioned after the
    /// preamble. A connection whose preamble is invalid is closed and
    /// reported; no state changes here.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept(&self) -> Result<TcpFrameTransport, StreamError> {
        let (socket, _peer) = self.listener.accept().map_err(|_| StreamError::Accept)?;
        self.validate(socket)
    }

    fn validate(&self, socket: TcpStream) -> Result<TcpFrameTransport, StreamError> {
        let mut transport =
            TcpFrameTransport::new(socket, &self.candidate_id, self.receive_deadline)
                .map_err(|_| StreamError::Accept)?;
        let preamble = transport.receive_frame().map_err(StreamError::Preamble)?;
        StreamPreamble::decode(&preamble)?;
        Ok(transport)
    }
}

/// Dials a listener and sends the pairing preamble, as the proxy side does.
/// Used by loopback tests and by a future Windows-hosted proxy.
///
/// # Errors
///
/// Fails when no endpoint accepts the connection or the preamble cannot be
/// sent.
pub fn dial(
    endpoints: &[String],
    candidate_id: &str,
    receive_deadline: Duration,
) -> Result<TcpFrameTransport, StreamError> {
    let preamble = StreamPreamble.encode()?;
    for endpoint in endpoints {
        let Ok(socket) = TcpStream::connect(endpoint.as_str()) else {
            continue;
        };
        let mut transport = TcpFrameTransport::new(socket, candidate_id, receive_deadline)
            .map_err(|_| StreamError::Accept)?;
        transport
            .send_frame(&preamble)
            .map_err(StreamError::Preamble)?;
        return Ok(transport);
    }
    Err(StreamError::Unreachable)
}

/// Rejected stream-profile bytes, parameters, or connection steps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamError {
    /// Structure, domain, or type was not exactly as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_STREAM_PREAMBLE_FRAME`].
    Oversized,
    /// Purpose string is not registered; the connection closes unanswered.
    UnknownPurpose,
    /// Candidate carried no endpoint or more than [`MAX_STREAM_ENDPOINTS`].
    EndpointCount,
    /// An endpoint literal was empty or exceeded
    /// [`MAX_STREAM_ENDPOINT_BYTES`].
    EndpointLength,
    /// The listener address could not be bound or reported.
    Bind,
    /// A connection could not be accepted or wrapped.
    Accept,
    /// The preamble frame could not be moved.
    Preamble(TransportError),
    /// No advertised endpoint accepted the connection.
    Unreachable,
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "test fixtures are constructed to be infallible"
)]
mod tests {
    use std::time::Duration;

    use super::{
        MAX_STREAM_ENDPOINTS, StreamError, StreamListener, StreamPreamble, dial,
        stream_candidate_endpoints, stream_candidate_parameters,
    };
    use crate::cbor::Value;
    use crate::transport::FrameTransport;

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";

    #[test]
    fn preamble_round_trips_and_rejects_foreign_purposes() {
        let pairing = StreamPreamble.encode().unwrap();
        assert!(pairing.len() <= super::MAX_STREAM_PREAMBLE_FRAME);
        assert_eq!(StreamPreamble::decode(&pairing).unwrap(), StreamPreamble);
        let retired = Value::Array(vec![
            Value::Text(super::STREAM_PREAMBLE_DOMAIN.to_owned()),
            Value::Text("session".to_owned()),
        ])
        .encode()
        .unwrap();
        assert_eq!(
            StreamPreamble::decode(&retired),
            Err(StreamError::UnknownPurpose)
        );
        let oversized = vec![0u8; super::MAX_STREAM_PREAMBLE_FRAME + 1];
        assert_eq!(
            StreamPreamble::decode(&oversized),
            Err(StreamError::Oversized)
        );
    }

    #[test]
    fn candidate_parameters_round_trip_and_bound() {
        let endpoints = vec!["192.0.2.10:47110".to_owned()];
        let parameters = stream_candidate_parameters(&endpoints).unwrap();
        assert_eq!(stream_candidate_endpoints(&parameters).unwrap(), endpoints);
        let excessive = vec!["192.0.2.10:47110".to_owned(); MAX_STREAM_ENDPOINTS + 1];
        assert_eq!(
            stream_candidate_parameters(&excessive),
            Err(StreamError::EndpointCount)
        );
    }

    #[test]
    fn listener_accepts_a_pairing_dial() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let endpoints = vec![format!("127.0.0.1:{port}")];

        let dialer = std::thread::spawn(move || {
            let mut transport = dial(&endpoints, CANDIDATE, DEADLINE).unwrap();
            // Prove the channel survives the preamble in both directions.
            transport.send_frame(&[0x01, 0x02]).unwrap();
        });
        let mut transport = listener.accept().unwrap();
        assert_eq!(transport.receive_frame().unwrap(), vec![0x01, 0x02]);
        dialer.join().unwrap();
    }

    #[test]
    fn garbage_preambles_close_without_classification() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let dialer = std::thread::spawn(move || {
            let socket = std::net::TcpStream::connect(format!("127.0.0.1:{port}")).unwrap();
            let mut transport =
                crate::transport::TcpFrameTransport::new(socket, CANDIDATE, DEADLINE).unwrap();
            transport.send_frame(&[0xFF, 0x00, 0x11]).unwrap();
        });
        assert!(matches!(listener.accept(), Err(StreamError::Malformed)));
        dialer.join().unwrap();
    }
}
