use async_recursion::async_recursion;
use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{flat_map, map},
    number::complete::{u16 as nomu16, u8 as nomu8},
    number::Endianness,
    sequence::tuple,
};
use std::error::Error;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::{Arc, Mutex};
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::select;
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};

type AnswerAndTransform =
    fn(Message) -> Result<(Vec<u8>, State, Option<TcpStream>), Box<dyn Error>>;
type MessageParser = fn(&[u8]) -> Result<(&[u8], Message), nom::Err<nom::error::Error<&[u8]>>>;

#[derive(PartialEq, Debug)]
enum State {
    Init,
    Authenticating,
    Authenticated,
    Connected,
}

#[derive(Debug)]
struct ClientGreeting {
    Ver: u8,
    Auth: Vec<u8>,
}

#[derive(Debug)]
struct ClientAuthRequest {
    Ver: u8,
    Id: Vec<u8>,
    Pw: Vec<u8>,
}

#[derive(Debug)]
struct ClientConnectionRequest {
    Ver: u8,
    Cmd: u8,
    Rsv: u8,
    Socks5Addr: Sock5AddressType,
    DstPort: u16,
}

#[derive(Debug)]
enum Message {
    ClientGreeting(ClientGreeting),
    ClientAuthRequest(ClientAuthRequest),
    ClientConnectionRequest(ClientConnectionRequest),
}

#[derive(Debug)]
enum Sock5AddressType {
    IPv4(Ipv4Addr),
    Domain(String),
    IPv6(Ipv6Addr),
}

fn get_message_parser(state: &State) -> MessageParser {
    match state {
        State::Init => |input| {
            map(
                tuple((nomu8, flat_map(nomu8, take))),
                |(ver, auth): (u8, &[u8])| {
                    Message::ClientGreeting(ClientGreeting {
                        Ver: ver,
                        Auth: auth.to_vec(),
                    })
                },
            )(input)
        },
        State::Authenticating => |input| {
            map(
                tuple((nomu8, flat_map(nomu8, take), flat_map(nomu8, take))),
                |(ver, id, pw): (_, &[u8], &[u8])| {
                    Message::ClientAuthRequest(ClientAuthRequest {
                        Ver: ver,
                        Id: id.to_vec(),
                        Pw: pw.to_vec(),
                    })
                },
            )(input)
        },
        State::Authenticated => |input| {
            let ipv4_parser = map(tuple((tag(&[1u8]), take(4u8))), |(_, ipv4): (_, &[u8])| {
                Sock5AddressType::IPv4(
                    Ipv4Addr::try_from(*std::convert::TryInto::<&[u8; 4]>::try_into(ipv4).unwrap())
                        .unwrap_or_else(|_| panic!("Could not parse IPv4 address: {:?}", ipv4)),
                )
            });

            let domain_parser = map(
                tuple((tag(&[3u8]), flat_map(nomu8, take))),
                |(_, domain): (_, &[u8])| {
                    Sock5AddressType::Domain(
                        String::from_utf8(domain.to_vec())
                            .unwrap_or_else(|_| panic!("Could not read domain: {:?}", domain)),
                    )
                },
            );

            let ipv6_parser = map(tuple((tag(&[4u8]), take(16u8))), |(_, ipv6): (_, &[u8])| {
                Sock5AddressType::IPv6(
                    Ipv6Addr::try_from(
                        *std::convert::TryInto::<&[u8; 16]>::try_into(ipv6).unwrap(),
                    )
                    .unwrap_or_else(|_| panic!("Could not parse IPv6 address: {:?}", ipv6)),
                )
            });

            map(
                tuple((
                    nomu8,
                    nomu8,
                    nomu8,
                    alt((ipv4_parser, domain_parser, ipv6_parser)),
                    nomu16(Endianness::Big),
                )),
                |(ver, cmd, rsv, dstaddr, dstport): (u8, u8, u8, Sock5AddressType, u16)| {
                    Message::ClientConnectionRequest(ClientConnectionRequest {
                        Ver: ver,
                        Cmd: cmd,
                        Rsv: rsv,
                        Socks5Addr: dstaddr,
                        DstPort: dstport,
                    })
                },
            )(input)
        },
        State::Connected => panic!("this should not happen!"),
    }
}

fn get_answer_and_transform(state: &State) -> AnswerAndTransform {
    match state {
        State::Init => todo!(),
        State::Authenticating => todo!(),
        State::Authenticated => todo!(),
        State::Connected => todo!(),
    }
}

async fn process(
    state: State,
    mut stream: TcpStream,
    mut buf: Vec<u8>,
) -> Result<(State, TcpStream, Option<TcpStream>), Box<dyn std::error::Error>> {
    buf.fill(0);

    // read message from stream
    let _ = stream.read_buf(&mut buf).await?;
    let (_, message) = get_message_parser(&state)(&buf)
        .unwrap_or_else(|_| panic!("parse error in state {:?} for data {:?}", state, buf));

    // write answer to stream
    let (answer, next_state, remote_stream) = get_answer_and_transform(&state)(message)?;
    stream.write_all(&answer).await?;

    // return next state and stream
    Ok((next_state, stream, remote_stream))
}

#[async_recursion]
async fn process_protocol(
    state: State,
    client_stream: TcpStream,
) -> Result<(State, TcpStream, TcpStream), Box<dyn std::error::Error>> {
    let buf = vec![0; 1024];
    let (next_state, client_stream, remote_stream) = process(state, client_stream, buf).await?;

    if next_state == State::Connected {
        return Ok((next_state, client_stream, remote_stream.unwrap()));
    }

    process_protocol(next_state, client_stream).await
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let listener = TcpListener::bind("0.0.0.0:8080").await?;
    loop {
        let (stream, _addr) = listener.accept().await?;

        tokio::spawn(async move {
            let (_, client_stream, remote_stream) = process_protocol(State::Init, stream)
                .await
                .expect("protocol error");

            // forward packets from client to target server and vice versa if connection was established
            let (mut cread, mut cwrite) = split(client_stream);
            let (mut rread, mut rwrite) = split(remote_stream);

            let forward = tokio::spawn(async move {
                if let Err(m) = copy(&mut cread, &mut rwrite).await {
                    eprintln!("error while forwarding client traffic {}", m)
                };

                rwrite.shutdown().await
            });
            let backward = tokio::spawn(async move {
                if let Err(m) = copy(&mut rread, &mut cwrite).await {
                    eprintln!("error while forwarding remote traffic: {}", m)
                };
                cwrite.shutdown().await
            });

            select! {
                _ = forward => (),
                _ = backward => (),
            }
        });
    }
}
