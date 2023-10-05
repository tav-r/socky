use async_recursion::async_recursion;
use itertools::{concat, Itertools};

use nom::{
    branch::alt,
    bytes::complete::{tag, take},
    combinator::{flat_map, map},
    number::complete::{u16 as nomu16, u8 as nomu8},
    number::Endianness,
    sequence::tuple,
};
use std::env::args;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use tokio::io::{copy, split, AsyncWriteExt};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
    select,
};

type Transformation = Result<(Vec<u8>, State, Option<String>), std::io::Error>;
type ResponseAndTransform = dyn Fn(Message) -> Transformation;
type MessageParser = fn(&[u8]) -> Result<(&[u8], Message), nom::Err<nom::error::Error<&[u8]>>>;

const SOCKS_VERSION: u8 = 5;
const PASSWORD_AUTH: u8 = 2;
const NO_AUTH: u8 = 0;

macro_rules! curry1 {
    ($func:expr, $x:expr) => {
        move |y| $func($x, y)
    };
}

#[derive(PartialEq, Debug)]
enum State {
    Init,
    Authenticating,
    Authenticated,
    Connected,
}

#[derive(Debug)]
struct ClientGreeting {
    auth: Vec<u8>,
}

#[derive(Debug)]
struct ClientAuthRequest {
    id: String,
    pw: String,
}

#[derive(Debug)]
struct ClientConnectionRequest {
    socks5_addr: Sock5AddressType,
    dstport: u16,
}

#[derive(Debug)]
enum Message {
    Greeting(ClientGreeting),
    AuthRequest(ClientAuthRequest),
    ConnectionRequest(ClientConnectionRequest),
}

#[derive(Debug)]
enum Sock5AddressType {
    IPv4(Ipv4Addr),
    Domain(String),
    IPv6(Ipv6Addr),
}

impl From<&Sock5AddressType> for String {
    fn from(val: &Sock5AddressType) -> Self {
        match val {
            Sock5AddressType::IPv4(ipv4) => ipv4.to_string(),
            Sock5AddressType::Domain(s) => s.clone(),
            Sock5AddressType::IPv6(ipv6) => ipv6.to_string(),
        }
    }
}

// Get the message parser for the current state
fn get_message_parser(state: &State) -> MessageParser {
    match state {
        // Expect Greeting Message, it consists of a version byte, the number of supported auth methods and the auth methods
        State::Init => |input| {
            map(
                tuple((
                    tag(&[5u8]),           // version, must be 0x05
                    flat_map(nomu8, take), // read the specified number of auth methods
                )),
                // transform the parsed data into a ClientGreeting struct wrapped in a Message enum
                |(_, auth): (&[u8], &[u8])| {
                    Message::Greeting(ClientGreeting {
                        auth: auth.to_vec(),
                    })
                },
            )(input)
        },
        // Expect Auth Request, it consists of a version byte, the username and the password
        State::Authenticating => |input| {
            map(
                tuple((
                    tag(&[1u8]),           // auth version, only username/password is supported
                    flat_map(nomu8, take), // read the specified number of username bytes
                    flat_map(nomu8, take), // read the specified number of password bytes
                )),
                // transform the parsed data into a ClientAuthRequest struct wrapped in a Message enum
                |(_, id, pw): (_, &[u8], &[u8])| {
                    Message::AuthRequest(ClientAuthRequest {
                        id: String::from_utf8(id.to_vec())
                            .unwrap_or_else(|_| panic!("could not parse username")),
                        pw: String::from_utf8(pw.to_vec())
                            .unwrap_or_else(|_| panic!("could not parse password")),
                    })
                },
            )(input)
        },
        // Expect Connection Request, it consists of a version byte, a command byte, a reserved byte, the address type and the destination port
        State::Authenticated => |input| {
            // define parsers for the different address types
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
                    tag(&[5u8]), // SOCKS5 version
                    tag(&[1u8]), // command, currently TCP Port Binding and UDP are not supported
                    tag(&[0u8]), // RSV must be 0x00
                    alt((ipv4_parser, domain_parser, ipv6_parser)),
                    nomu16(Endianness::Big),
                )),
                // transform the parsed data into a ClientConnectionRequest struct wrapped in a Message enum
                |(_, _, _, dstaddr, dstport): (_, _, _, Sock5AddressType, u16)| {
                    Message::ConnectionRequest(ClientConnectionRequest {
                        socks5_addr: dstaddr,
                        dstport,
                    })
                },
            )(input)
        },
        State::Connected => panic!("tried to parse message in connected state"),
    }
}

fn init_message_transform_auth(message: Message) -> Transformation {
    match message {
        Message::Greeting(m) => {
            if m.auth.contains(&PASSWORD_AUTH) {
                Ok((
                    vec![SOCKS_VERSION, PASSWORD_AUTH],
                    State::Authenticating,
                    None,
                ))
            } else {
                // if anonymous auth is not supported, just close the connection
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported authentication method(s)",
                ))
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid message",
        )),
    }
}

fn init_message_transform_anon(message: Message) -> Transformation {
    match message {
        Message::Greeting(m) => {
            if m.auth.contains(&NO_AUTH) {
                Ok((vec![SOCKS_VERSION, NO_AUTH], State::Authenticated, None))
            } else {
                // if anonymous auth is not supported, just close the connection
                Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "unsupported authentication method(s)",
                ))
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid message",
        )),
    }
}

fn auth_message_transform(auth_info: Option<Arc<AuthInfo>>, message: Message) -> Transformation {
    match message {
        Message::AuthRequest(m) => {
            if let Some((username, password)) = auth_info
                .as_ref()
                .map(|a| (String::from(&a.username), String::from(&a.password)))
            {
                if m.id.eq(&username) && m.pw.eq(&password) {
                    Ok((
                        vec![SOCKS_VERSION, PASSWORD_AUTH],
                        State::Authenticated,
                        None,
                    ))
                } else {
                    println!("Authentication failed");
                    Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        "invalid username or password",
                    ))
                }
            } else {
                Ok((vec![SOCKS_VERSION, NO_AUTH], State::Authenticated, None))
            }
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid message or unsupported authentication method",
        )),
    }
}

fn connect_message_transform(message: Message) -> Transformation {
    match message {
        Message::ConnectionRequest(m) => {
            let target = format!(
                "{}:{}",
                std::convert::Into::<String>::into(&m.socks5_addr),
                m.dstport
            );

            Ok((
                vec![5, 0, 0]
                    .into_iter()
                    .chain(concat(match m.socks5_addr {
                        Sock5AddressType::IPv4(ipv4) => [vec![1], ipv4.octets().to_vec()],
                        Sock5AddressType::Domain(domain) => {
                            [vec![3, domain.len() as u8], domain.as_bytes().to_vec()]
                        }
                        Sock5AddressType::IPv6(ipv6) => [vec![4], ipv6.octets().to_vec()],
                    }))
                    .chain(m.dstport.to_be_bytes().to_vec())
                    .collect::<Vec<u8>>(),
                State::Connected,
                Some(target),
            ))
        }
        _ => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid message",
        )),
    }
}

// Get a function that returns the response to the given message, the next state and optionally a connection string
fn get_reponse_and_transform(
    state: &State,
    auth_info: Option<Arc<AuthInfo>>,
) -> Box<ResponseAndTransform> {
    let auth_required = auth_info.is_some();

    match state {
        // Return "password authentication" response if the client supports it, otherwise return "no acceptable authentication methods
        State::Init => {
            if auth_required {
                Box::new(init_message_transform_auth)
            } else {
                Box::new(init_message_transform_anon)
            }
        }
        // Return "authentication successful" response if the username and password are correct, otherwise return "authentication failed"
        State::Authenticating => Box::new(curry1!(auth_message_transform, auth_info.clone())),
        // Return "connection established" response and the connection string
        State::Authenticated => Box::new(connect_message_transform),
        State::Connected => panic!("tried to get response in connected state"),
    }
}

async fn process(
    state: State,
    mut stream: TcpStream,
    buf: &mut [u8],
    config: Option<Arc<AuthInfo>>,
) -> Result<(State, TcpStream, Option<TcpStream>), Box<dyn std::error::Error>> {
    // read from stream
    let n = stream.read(buf).await?;

    // parse message
    let (_, message) = get_message_parser(&state)(&buf[..n]).map_err(|e| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("parse error in state {:?} for data {:?}: {}", state, buf, e),
        )
    })?;

    // get response and next state
    let (response, next_state, conn_string) = get_reponse_and_transform(&state, config)(message)?;

    // connect to remote if necessary
    let remote_stream = if let Some(conn_string) = conn_string {
        Some(TcpStream::connect(conn_string).await?)
    } else {
        None
    };

    // write response to stream
    stream.write_all(&response).await?;

    // return next state and stream
    Ok((next_state, stream, remote_stream))
}

#[async_recursion]
async fn process_protocol(
    state: State,
    client_stream: TcpStream,
    config: Option<Arc<AuthInfo>>,
) -> Result<(State, TcpStream, TcpStream), Box<dyn std::error::Error>> {
    let mut buf = [0u8; 1024];
    let (next_state, client_stream, remote_stream) =
        process(state, client_stream, &mut buf, config.clone()).await?;

    match next_state {
        State::Connected => Ok((
            next_state,
            client_stream,
            remote_stream
                .ok_or("reached 'Connected' state but remote connection was not established")?,
        )),
        _ => process_protocol(next_state, client_stream, config).await,
    }
}

#[derive(Debug)]
struct AuthInfo {
    pub username: String,
    pub password: String,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arguments = args().skip(1);

    let bind_string = arguments.next().ok_or("No bind string provided")?;

    let auth_info = arguments
        .next()
        .map(|s| {
            s.splitn(2, ':')
                .collect_tuple()
                .map(|(u, p)| {
                    Arc::new(AuthInfo {
                        username: u.to_string(),
                        password: p.to_string(),
                    })
                })
                .ok_or("Invalid auth info")
        })
        .transpose()?;

    let listener = TcpListener::bind(&bind_string).await?;

    loop {
        let (stream, _addr) = listener.accept().await?;

        let auth_info = auth_info.clone();

        tokio::spawn(async move {
            let (_, client_stream, remote_stream) =
                process_protocol(State::Init, stream, auth_info)
                    .await
                    .unwrap_or_else(|e| {
                        eprintln!("error while processing protocol: {}", e);
                        panic!()
                    });

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
