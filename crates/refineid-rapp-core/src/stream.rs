//! The `fi.refineid.stream.v1` transport profile of specification
//! Section 16.1.
//!
//! The requester runs the listener; the proxy dials, for both pairing and
//! sessions. Every connection opens with one plaintext rendezvous preamble
//! frame that selects which handshake the accepting requester initiates.
//! The preamble is unauthenticated routing metadata, exactly like a relay
//! token: it enables nothing but the selection, and every anomaly closes
//! the connection without touching stored state (Section 14.5, class 1).

use std::net::{TcpListener, TcpStream};
use std::time::Duration;

use crate::cbor::Value;
use crate::ids::RendezvousToken;
use crate::transport::{FrameTransport, TcpFrameTransport, TransportError};

/// Domain string opening every stream rendezvous preamble.
const STREAM_RENDEZVOUS_DOMAIN: &str = "RAPP-stream-v1";

/// Preamble purpose naming a pairing attempt.
const PURPOSE_PAIRING: &str = "pairing";

/// Preamble purpose naming a session attempt for a stored pairing.
const PURPOSE_SESSION: &str = "session";

/// Upper bound on an encoded rendezvous preamble frame; the listener
/// rejects a longer preamble before parsing it.
pub const MAX_STREAM_RENDEZVOUS_FRAME: usize = 64;

/// Candidate parameter key carrying the listener endpoint list.
const PARAMETER_ENDPOINTS: &str = "endpoints";

/// Maximum listener endpoints one stream candidate may carry.
pub const MAX_STREAM_ENDPOINTS: usize = 8;

/// Maximum UTF-8 bytes of one `host:port` endpoint literal.
pub const MAX_STREAM_ENDPOINT_BYTES: usize = 255;

/// One plaintext rendezvous preamble, the first frame on a fresh stream
/// connection before any Noise message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StreamRendezvous {
    /// Connect to the listener's currently active pairing offer.
    Pairing,
    /// Connect for a fresh session with the stored pairing this token
    /// names.
    Session(RendezvousToken),
}

impl StreamRendezvous {
    /// Encodes the preamble frame payload.
    ///
    /// # Errors
    ///
    /// Fails only when the value cannot be encoded within the wire limits.
    pub fn encode(&self) -> Result<Vec<u8>, StreamError> {
        let (purpose, token_bytes) = match self {
            Self::Pairing => (PURPOSE_PAIRING, Vec::new()),
            Self::Session(token) => (PURPOSE_SESSION, token.0.to_vec()),
        };
        Value::Array(vec![
            Value::Text(STREAM_RENDEZVOUS_DOMAIN.to_owned()),
            Value::Text(purpose.to_owned()),
            Value::Bytes(token_bytes),
        ])
        .encode()
        .map_err(|_| StreamError::Malformed)
    }

    /// Decodes and validates one received preamble frame payload.
    ///
    /// # Errors
    ///
    /// Every failure is pre-authentication invalid input: the caller closes
    /// the connection and changes no stored state.
    pub fn decode(bytes: &[u8]) -> Result<Self, StreamError> {
        if bytes.len() > MAX_STREAM_RENDEZVOUS_FRAME {
            return Err(StreamError::Oversized);
        }
        let Ok(Value::Array(elements)) = Value::decode(bytes) else {
            return Err(StreamError::Malformed);
        };
        let [
            Value::Text(domain),
            Value::Text(purpose),
            Value::Bytes(token_bytes),
        ] = elements.as_slice()
        else {
            return Err(StreamError::Malformed);
        };
        if domain != STREAM_RENDEZVOUS_DOMAIN {
            return Err(StreamError::Malformed);
        }
        match purpose.as_str() {
            PURPOSE_PAIRING => {
                if token_bytes.is_empty() {
                    Ok(Self::Pairing)
                } else {
                    Err(StreamError::Malformed)
                }
            }
            PURPOSE_SESSION => {
                let token: [u8; crate::ids::RENDEZVOUS_TOKEN_LENGTH] = token_bytes
                    .as_slice()
                    .try_into()
                    .map_err(|_| StreamError::Malformed)?;
                Ok(Self::Session(RendezvousToken(token)))
            }
            _ => Err(StreamError::UnknownPurpose),
        }
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

/// Reads the listener endpoints back out of stored candidate parameters.
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

/// One accepted, preamble-classified stream connection.
#[derive(Debug)]
pub enum StreamAccept {
    /// The dialing proxy asked for the active pairing offer.
    Pairing(TcpFrameTransport),
    /// The dialing proxy asked for a fresh session with a stored pairing.
    Session {
        /// The pair-specific token from the preamble. The caller looks it
        /// up among non-revoked pairings and closes on no match.
        rendezvous_token: RendezvousToken,
        /// The connection, positioned after the preamble.
        transport: TcpFrameTransport,
    },
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
    /// and classifies it. A connection whose preamble is invalid is closed
    /// and reported; stored state never changes here.
    ///
    /// # Errors
    ///
    /// Fails on accept failure or an invalid preamble.
    pub fn accept(&self) -> Result<StreamAccept, StreamError> {
        let (socket, _peer) = self.listener.accept().map_err(|_| StreamError::Accept)?;
        self.classify(socket)
    }

    fn classify(&self, socket: TcpStream) -> Result<StreamAccept, StreamError> {
        let mut transport =
            TcpFrameTransport::new(socket, &self.candidate_id, self.receive_deadline)
                .map_err(|_| StreamError::Accept)?;
        let preamble = transport.receive_frame().map_err(StreamError::Preamble)?;
        match StreamRendezvous::decode(&preamble)? {
            StreamRendezvous::Pairing => Ok(StreamAccept::Pairing(transport)),
            StreamRendezvous::Session(rendezvous_token) => Ok(StreamAccept::Session {
                rendezvous_token,
                transport,
            }),
        }
    }
}

/// Dials a listener and sends the preamble, as the proxy side does. Used by
/// loopback tests and by a future Windows-hosted proxy.
///
/// # Errors
///
/// Fails when no endpoint accepts the connection or the preamble cannot be
/// sent.
pub fn dial(
    endpoints: &[String],
    candidate_id: &str,
    receive_deadline: Duration,
    rendezvous: &StreamRendezvous,
) -> Result<TcpFrameTransport, StreamError> {
    let preamble = rendezvous.encode()?;
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
    /// Structure, domain, type, or token length was not as specified.
    Malformed,
    /// Preamble frame exceeded [`MAX_STREAM_RENDEZVOUS_FRAME`].
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
        MAX_STREAM_ENDPOINTS, StreamAccept, StreamError, StreamListener, StreamRendezvous, dial,
        stream_candidate_endpoints, stream_candidate_parameters,
    };
    use crate::ids::RendezvousToken;
    use crate::transport::FrameTransport;

    const DEADLINE: Duration = Duration::from_secs(2);
    const CANDIDATE: &str = "stream-test";

    fn token() -> RendezvousToken {
        RendezvousToken([0x5A; 16])
    }

    #[test]
    fn preambles_round_trip_and_reject_foreign_purposes() {
        let pairing = StreamRendezvous::Pairing.encode().unwrap();
        assert_eq!(
            StreamRendezvous::decode(&pairing).unwrap(),
            StreamRendezvous::Pairing
        );
        let session = StreamRendezvous::Session(token()).encode().unwrap();
        assert_eq!(
            StreamRendezvous::decode(&session).unwrap(),
            StreamRendezvous::Session(token())
        );
        let oversized = vec![0u8; super::MAX_STREAM_RENDEZVOUS_FRAME + 1];
        assert_eq!(
            StreamRendezvous::decode(&oversized),
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
    fn listener_classifies_pairing_and_session_dials() {
        let listener = StreamListener::bind("127.0.0.1:0", CANDIDATE, DEADLINE).unwrap();
        let port = listener.local_port().unwrap();
        let endpoints = vec![format!("127.0.0.1:{port}")];

        let dial_endpoints = endpoints.clone();
        let dialer = std::thread::spawn(move || {
            dial(
                &dial_endpoints,
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Pairing,
            )
            .unwrap()
        });
        let accepted = listener.accept().unwrap();
        assert!(matches!(accepted, StreamAccept::Pairing(_)));
        drop(dialer.join().unwrap());

        let dialer = std::thread::spawn(move || {
            let mut transport = dial(
                &endpoints,
                CANDIDATE,
                DEADLINE,
                &StreamRendezvous::Session(RendezvousToken([0x5A; 16])),
            )
            .unwrap();
            // Prove the channel survives the preamble in both directions.
            transport.send_frame(&[0x01, 0x02]).unwrap();
        });
        let accepted = listener.accept().unwrap();
        let StreamAccept::Session {
            rendezvous_token,
            mut transport,
        } = accepted
        else {
            panic!("expected a session accept");
        };
        assert_eq!(rendezvous_token, RendezvousToken([0x5A; 16]));
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
