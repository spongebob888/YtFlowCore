use serde::Deserialize;

use crate::config::factory::*;
use crate::config::*;

fn default_quic_cc() -> &'static str {
    "bbr"
}

#[cfg_attr(not(feature = "plugins"), allow(dead_code))]
#[derive(Deserialize)]
pub struct QuicClientFactory<'a> {
    sni: Option<&'a str>,
    #[serde(borrow, default)]
    alpn: Vec<&'a str>,
    #[serde(default)]
    zero_rtt: bool,
    #[serde(default)]
    skip_cert_check: bool,
    #[serde(default = "default_quic_cc")]
    congestion_ctrl: &'a str,
    next: &'a str,
}

impl<'de> QuicClientFactory<'de> {
    pub(in super::super) fn parse(plugin: &'de Plugin) -> ConfigResult<ParsedPlugin<'de, Self>> {
        let Plugin { name, param, .. } = plugin;
        let config: Self = parse_param(name, param)?;
        let next = config.next;
        Ok(ParsedPlugin {
            factory: config,
            requires: vec![Descriptor {
                descriptor: next,
                r#type: AccessPointType::DATAGRAM_SESSION_FACTORY,
            }],
            provides: vec![Descriptor {
                descriptor: name.to_string() + ".tcp",
                r#type: AccessPointType::STREAM_OUTBOUND_FACTORY,
            }],
            resources: vec![],
        })
    }
}

impl<'de> Factory for QuicClientFactory<'de> {
    #[cfg(feature = "plugins")]
    fn load(&mut self, plugin_name: String, set: &mut PartialPluginSet) -> LoadResult<()> {
        use crate::plugin::null::Null;
        use crate::plugin::quic;

        let factory = Arc::new_cyclic(|weak| {
            set.stream_outbounds
                .insert(plugin_name.clone() + ".tcp", weak.clone() as _);
            let next = match set.get_or_create_datagram_outbound(plugin_name.clone(), self.next) {
                Ok(next) => next,
                Err(e) => {
                    set.errors.push(e);
                    Arc::downgrade(&(Arc::new(Null)))
                }
            };

            quic::QuicOutboundFactory::new(
                next,
                std::mem::take(&mut self.alpn),
                self.skip_cert_check,
                self.sni.map(|s| s.to_string()),
                self.zero_rtt,
                self.congestion_ctrl,
            )
        });
        set.fully_constructed
            .stream_outbounds
            .insert(plugin_name + ".tcp", factory);
        Ok(())
    }
}
