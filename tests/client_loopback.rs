use std::io::ErrorKind;
use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::thread;
use std::time::{Duration, Instant};

use stun::{
    Attribute, Class, Endpoint, Error, ErrorCode, Message, Method, RetransmitSchedule, StunClient,
    TransactionId,
};

fn server() -> (UdpSocket, Endpoint) {
    let socket = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    (socket, Endpoint::new("127.0.0.1", port))
}

fn receive_request(socket: &UdpSocket) -> (Message, SocketAddr) {
    let mut buf = [0u8; 1500];
    let (n, peer) = socket.recv_from(&mut buf).unwrap();
    let message = Message::decode(&buf[..n]).unwrap();
    assert_eq!(message.class(), Class::Request);
    (message, peer)
}

fn response(request: &Message, class: Class, attributes: Vec<Attribute>) -> Vec<u8> {
    let mut builder =
        Message::builder(Method::Binding, class).transaction_id(*request.transaction_id());
    for attribute in attributes {
        builder = builder.attribute(attribute);
    }
    builder.with_fingerprint().build_and_encode().unwrap()
}

fn fast_client() -> StunClient {
    StunClient::new().rto(Duration::from_millis(40))
}

fn answer_with(
    socket: UdpSocket,
    reply: impl FnOnce(&UdpSocket, &Message, SocketAddr) + Send + 'static,
) -> thread::JoinHandle<SocketAddr> {
    thread::spawn(move || {
        let (request, peer) = receive_request(&socket);
        reply(&socket, &request, peer);
        peer
    })
}

#[test]
fn bind_returns_the_address_the_server_saw() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![Attribute::XorMappedAddress(peer)],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let mapped = fast_client().bind(&endpoint).unwrap();
    assert_eq!(mapped, server.join().unwrap());
}

#[test]
fn unrelated_datagrams_do_not_use_up_retransmissions() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let other_transaction = Message::builder(Method::Binding, Class::SuccessResponse)
            .transaction_id(TransactionId::from_bytes([0xaa; 12]))
            .attribute(Attribute::XorMappedAddress("192.0.2.1:9".parse().unwrap()))
            .build_and_encode()
            .unwrap();
        let echoed_request = request.encode();
        for _ in 0..10 {
            socket.send_to(b"not a STUN message", peer).unwrap();
            socket.send_to(&other_transaction, peer).unwrap();
            socket.send_to(&echoed_request, peer).unwrap();
        }
        thread::sleep(Duration::from_millis(150));
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![Attribute::XorMappedAddress(peer)],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let mapped = fast_client().bind(&endpoint).unwrap();
    assert_eq!(mapped, server.join().unwrap());
}

#[test]
fn error_response_ends_the_transaction_at_once() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let reply = response(
            request,
            Class::ErrorResponse,
            vec![Attribute::ErrorCode(ErrorCode::new(401, "Unauthorized"))],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let started = Instant::now();
    let result = StunClient::new().bind(&endpoint);
    server.join().unwrap();
    match result {
        Err(Error::ErrorResponse(code)) => {
            assert_eq!(code.code(), 401);
            assert_eq!(code.reason, "Unauthorized");
        }
        other => panic!("expected an error response, got {other:?}"),
    }
    assert!(started.elapsed() < Duration::from_secs(5));
}

#[test]
fn error_response_without_error_code_fails() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let reply = response(request, Class::ErrorResponse, Vec::new());
        socket.send_to(&reply, peer).unwrap();
    });
    let result = fast_client().bind(&endpoint);
    server.join().unwrap();
    assert!(
        matches!(result, Err(Error::MalformedAttribute(_))),
        "{result:?}"
    );
}

#[test]
fn a_response_from_another_address_is_not_accepted() {
    let (socket, endpoint) = server();
    let stray = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let server = answer_with(socket, move |socket, request, peer| {
        let forged = response(
            request,
            Class::SuccessResponse,
            vec![Attribute::XorMappedAddress(
                "203.0.113.9:1".parse().unwrap(),
            )],
        );
        stray.send_to(&forged, peer).unwrap();
        thread::sleep(Duration::from_millis(100));
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![Attribute::XorMappedAddress(peer)],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let mapped = fast_client().bind(&endpoint).unwrap();
    assert_eq!(mapped, server.join().unwrap());
}

#[test]
fn silent_server_times_out_after_seven_requests_and_the_socket_is_closed() {
    let (socket, endpoint) = server();
    let rto = Duration::from_millis(10);
    let schedule: Duration = RetransmitSchedule::with_rto(rto).sum();
    assert_eq!(schedule, rto * 79);

    let started = Instant::now();
    let result = StunClient::new().rto(rto).bind(&endpoint);
    let elapsed = started.elapsed();
    assert!(matches!(result, Err(Error::Timeout)), "{result:?}");
    assert!(elapsed >= schedule, "{elapsed:?}");

    socket
        .set_read_timeout(Some(Duration::from_millis(200)))
        .unwrap();
    let mut buf = [0u8; 1500];
    let mut requests = 0;
    let mut peer = None;
    while let Ok((_, from)) = socket.recv_from(&mut buf) {
        requests += 1;
        peer = Some(from);
    }
    assert_eq!(requests, 7);

    socket.connect(peer.unwrap()).unwrap();
    let refused = |error: &std::io::Error| error.kind() == ErrorKind::ConnectionRefused;
    let closed = (0..50).any(|_| match socket.send(b"probe") {
        Err(error) => refused(&error),
        Ok(_) => matches!(socket.recv(&mut buf), Err(ref error) if refused(error)),
    });
    assert!(
        closed,
        "the client socket is still open after bind returned"
    );
}

#[test]
fn unknown_comprehension_required_attribute_fails_the_transaction() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![
                Attribute::XorMappedAddress(peer),
                Attribute::Unknown {
                    attribute_type: 0x7f00,
                    value: vec![1, 2, 3, 4],
                },
                Attribute::Unknown {
                    attribute_type: 0x8f00,
                    value: vec![5],
                },
            ],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let result = fast_client().bind(&endpoint);
    server.join().unwrap();
    match result {
        Err(Error::UnknownAttributes(types)) => assert_eq!(types, [0x7f00]),
        other => panic!("expected unknown attributes, got {other:?}"),
    }
}

#[test]
fn rfc3489_source_and_changed_address_are_tolerated() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let legacy_address = vec![0, 1, 0x0d, 0x96, 192, 0, 2, 1];
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![
                Attribute::MappedAddress(peer),
                Attribute::Unknown {
                    attribute_type: 0x0004,
                    value: legacy_address.clone(),
                },
                Attribute::Unknown {
                    attribute_type: 0x0005,
                    value: legacy_address,
                },
            ],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let mapped = fast_client().bind(&endpoint).unwrap();
    assert_eq!(mapped, server.join().unwrap());
}

#[test]
fn oversized_datagrams_are_skipped() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        socket.send_to(&[0u8; 3000], peer).unwrap();
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![Attribute::XorMappedAddress(peer)],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let mapped = fast_client().bind(&endpoint).unwrap();
    assert_eq!(mapped, server.join().unwrap());
}

#[test]
fn success_response_without_a_mapped_address_fails() {
    let (socket, endpoint) = server();
    let server = answer_with(socket, |socket, request, peer| {
        let reply = response(
            request,
            Class::SuccessResponse,
            vec![Attribute::Software("x".into())],
        );
        socket.send_to(&reply, peer).unwrap();
    });
    let result = fast_client().bind(&endpoint);
    server.join().unwrap();
    assert!(
        matches!(result, Err(Error::MalformedAttribute(_))),
        "{result:?}"
    );
}
