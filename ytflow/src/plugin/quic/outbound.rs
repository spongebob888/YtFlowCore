use crate::flow::*;
use async_trait::async_trait;
use core::panic;
use log::{debug, error, info};
use quinn::{self, AsyncUdpSocket};
use rustls::{OwnedTrustAnchor, RootCertStore};
use std::fmt::Debug;
use std::io::{self, Error};
use std::net::SocketAddr;
use std::pin::Pin;

use std::sync::{Arc, RwLock, Weak};
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::Mutex;

pub struct QuicOutboundFactory {
    cfg: quinn::ClientConfig,
    sni: Option<String>,
    zero_rtt: bool,
    conn: Mutex<Option<quinn::Connection>>,
    next: Weak<dyn DatagramSessionFactory>,
}
impl QuicOutboundFactory {
    pub fn new(
        next: Weak<dyn DatagramSessionFactory>,
        alpns: Vec<&str>,
        skip_cert_check: bool,
        sni: Option<String>,
        zero_rtt: bool,
        congestion_ctrl: &str,
    ) -> QuicOutboundFactory {
        let mut root_store = RootCertStore::empty();
        root_store.add_trust_anchors(webpki_roots::TLS_SERVER_ROOTS.iter().map(|ta| {
            OwnedTrustAnchor::from_subject_spki_name_constraints(
                ta.subject,
                ta.spki,
                ta.name_constraints,
            )
        }));
        let mut client_crypto = rustls::ClientConfig::builder()
            .with_safe_defaults()
            .with_root_certificates(root_store)
            .with_no_client_auth();
        if skip_cert_check {
            client_crypto
                .dangerous()
                .set_certificate_verifier(SkipServerVerification::new());
        }
        client_crypto.enable_early_data = zero_rtt;
        // client_crypto.jls_config = JlsConfig::new(&jls_pwd, &jls_iv);
        for alpn in alpns {
            client_crypto.alpn_protocols.push(alpn.as_bytes().to_vec());
        }

        let mut client_config = quinn::ClientConfig::new(Arc::new(client_crypto));
        let mut transport_config = quinn::TransportConfig::default();
        transport_config.max_idle_timeout(Some(quinn::IdleTimeout::from(quinn::VarInt::from_u32(
            300_000,
        )))); // ms

        match congestion_ctrl {
            "bbr" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::BbrConfig::default(),
                ));
            }
            "cubic" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::CubicConfig::default(),
                ));
            }
            "newreno" => {
                transport_config.congestion_controller_factory(Arc::new(
                    quinn::congestion::NewRenoConfig::default(),
                ));
            }
            _ => {
                error!("congestion controller not supported");
            }
        };
        transport_config.enable_segmentation_offload(false);
        client_config.transport_config(Arc::new(transport_config));
        QuicOutboundFactory {
            cfg: client_config,
            sni,
            zero_rtt,
            conn: Mutex::new(None),
            next,
        }
    }
}

fn quic_err<E>(error: E) -> FlowError
where
    E: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    FlowError::Io(std::io::Error::new(std::io::ErrorKind::Other, error))
}
#[async_trait]
impl StreamOutboundFactory for QuicOutboundFactory {
    async fn create_outbound(
        &self,
        context: &mut FlowContext,
        initial_data: &[u8],
    ) -> FlowResult<(Box<dyn Stream>, Buffer)> {
        let lower_factory = self.next.upgrade().ok_or(FlowError::NoOutbound)?;
        let ctx_clone = Box::new(FlowContext {
            local_peer: context.local_peer,
            remote_peer: context.remote_peer.clone(),
            af_sensitive: context.af_sensitive,
            application_layer_protocol: context.application_layer_protocol.clone(),
        });

        let lower = lower_factory.bind(ctx_clone).await?;

        let udpwrapper = UdpWrapper {
            _local_ip: "0.0.0.0:0".parse().unwrap(),
            inner: RwLock::new(lower),
        };

        let runtime = quinn::default_runtime()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "no async runtime found"))?;
        let mut ep = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            udpwrapper,
            runtime,
        )
        .expect("create quinn endpoint failed");
        ep.set_default_client_config(self.cfg.clone());

        let sni = if let Some(sni) = self.sni.clone() {
            sni
        } else {
            let host = context.remote_peer.host.to_string();
            host
        };
        let addr = match context.remote_peer.host {
            HostName::Ip(ip) => SocketAddr::new(ip, context.remote_peer.port),
            _ => panic!("host Name resolvation not implemented"),
        };
        let mut reason = None;
        let mut conn_read = self.conn.lock().await;
        if let Some(conn) = &*conn_read {
            reason = conn.close_reason();
            if let Some(ref reason) = reason {
                debug!("quic connection closed due to {}", reason);
            }
        }
        if conn_read.is_none() || reason.is_some() {
            let connecting = ep.connect(addr, &sni).map_err(|x| {
                FlowError::Io(std::io::Error::new(
                    std::io::ErrorKind::AddrNotAvailable,
                    x.to_string(),
                ))
            })?;
            let new_conn = if self.zero_rtt {
                match connecting.into_0rtt() {
                    Ok((new_conn, zero_rtt_accept)) => {
                        tokio::spawn(async move {
                            if zero_rtt_accept.await {
                                info!("[quic] zero rtt accepted");
                            } else {
                                info!("[quic] zero rtt rejected");
                            }
                        });
                        new_conn
                    }
                    Err(conn) => {
                        info!("[quic] zero rtt not available");
                        conn.await.map_err(quic_err)?
                    }
                }
            } else {
                connecting.await.map_err(quic_err)?
            };

            debug!("quic connection established");
            conn_read.replace(new_conn);
        }
        if let Some(conn) = &*conn_read {
            let (send, recv) = conn.open_bi().await.map_err(|x| {
                FlowError::Io(std::io::Error::new(
                    std::io::ErrorKind::Other,
                    x.to_string(),
                ))
            })?;
            debug!("quic bistream opened");
            //expect("Quic connect failed").await.unwrap();
            let mut inner = StreamUnsplit { send, recv };
            inner.write_all(initial_data).await?;
            let compat = CompatFlow::new(inner, 4096);
            Ok((Box::new(compat), Buffer::new()))
        } else {
            panic!("No quic connection got") // Impossible to happen I
        }
    }
}

struct StreamUnsplit<S, R> {
    send: S,
    recv: R,
}
impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncRead for StreamUnsplit<S, R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let recv = Pin::new(&mut self.recv);
        recv.poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin, R: AsyncRead + Unpin> AsyncWrite for StreamUnsplit<S, R> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<Result<usize, Error>> {
        let send = Pin::new(&mut self.send);
        send.poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let send = Pin::new(&mut self.send);
        send.poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Error>> {
        let send = Pin::new(&mut self.send);
        send.poll_shutdown(cx)
    }
}

struct UdpWrapper {
    _local_ip: SocketAddr, // Can't find a way to get local ip
    inner: RwLock<Box<dyn DatagramSession>>,
}
impl Debug for UdpWrapper {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Wrapped Udp Socket").finish()
    }
}

impl AsyncUdpSocket for UdpWrapper {
    fn poll_send(
        &self,
        _state: &quinn::udp::UdpState,
        cx: &mut std::task::Context,
        transmits: &[quinn::udp::Transmit],
    ) -> std::task::Poll<Result<usize, std::io::Error>> {
        let mut num_tx: usize = 0;
        let mut inner = self.inner.write().unwrap();
        for trans in transmits {
            match inner.poll_send_ready(cx) {
                Poll::Pending => {
                    if num_tx > 0 {
                        return Poll::Ready(Ok(num_tx));
                    } else {
                        return Poll::Pending;
                    }
                }
                Poll::Ready(()) => (),
            }

            assert!(trans.segment_size == None, "Segmentation Not supported");
            let port = trans.destination.port();
            let ip = trans.destination.ip();
            let dst = DestinationAddr {
                host: HostName::Ip(ip),
                port,
            };

            inner.send_to(dst, trans.contents.to_vec());
            num_tx += 1
        }
        if inner.poll_send_ready(cx) == Poll::Pending {
            // Tell lower to send
            return Poll::Pending;
        }
        return Poll::Ready(Ok(num_tx));
    }

    fn poll_recv(
        &self,
        cx: &mut std::task::Context,
        bufs: &mut [std::io::IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let mut inner = self.inner.write().unwrap();
        let mut msg_num = 0;
        loop {
            match inner.poll_recv_from(cx) {
                Poll::Ready(Some((dst, buffer))) => {
                    bufs[msg_num][0..buffer.len()].copy_from_slice(&buffer);
                    meta[msg_num].dst_ip = None;
                    meta[msg_num].len = buffer.len();

                    meta[msg_num].addr = match dst.host {
                        HostName::Ip(addr) => std::net::SocketAddr::new(addr, dst.port),
                        HostName::DomainName(_) => {
                            return Poll::Ready(Err(Error::new(
                                std::io::ErrorKind::Unsupported,
                                "Domainname type is not supported. Only Ip is supported",
                            )));
                        }
                    };
                    meta[msg_num].stride = buffer.len();
                    msg_num = msg_num + 1;
                    if msg_num == bufs.len() {
                        return Poll::Ready(Ok(msg_num));
                    }
                }
                Poll::Pending => {
                    if msg_num > 0 {
                        return Poll::Ready(Ok(msg_num));
                    } else {
                        return Poll::Pending;
                    }
                }
                Poll::Ready(None) => {
                    return Poll::Ready(Err(Error::new(
                        std::io::ErrorKind::UnexpectedEof,
                        "socket not available",
                    )));
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        return Ok(self._local_ip);
    }

    fn may_fragment(&self) -> bool {
        false
    }
}

// Implementation of `ServerCertVerifier` that verifies everything as trustworthy.
struct SkipServerVerification;

impl SkipServerVerification {
    fn new() -> Arc<Self> {
        Arc::new(Self)
    }
}

impl rustls::client::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::Certificate,
        _intermediates: &[rustls::Certificate],
        _server_name: &rustls::ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: std::time::SystemTime,
    ) -> Result<rustls::client::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::ServerCertVerified::assertion())
    }
}
