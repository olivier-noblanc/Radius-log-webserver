use actix::prelude::*;
use actix_web::{web, Error, HttpRequest, HttpResponse};
use actix_web_actors::ws;
use std::sync::Arc;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use crate::infrastructure::MessageBroadcaster;
use crate::utils::security::is_authorized;

const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(10);

pub struct WsSession {
    pub id: usize,
    pub hb: Instant,
    pub broadcaster: Arc<Broadcaster>,
}

impl Actor for WsSession {
    type Context = ws::WebsocketContext<Self>;

    fn started(&mut self, ctx: &mut Self::Context) {
        self.hb(ctx);
        self.broadcaster.sessions.insert(self.id, ctx.address().recipient());
    }

    fn stopping(&mut self, _: &mut Self::Context) -> Running {
        self.broadcaster.sessions.remove(&self.id);
        Running::Stop
    }
}

impl WsSession {
    fn hb(&self, ctx: &mut <Self as Actor>::Context) {
        ctx.run_interval(HEARTBEAT_INTERVAL, |act, ctx| {
            if Instant::now().duration_since(act.hb) > CLIENT_TIMEOUT {
                ctx.stop();
                return;
            }
            ctx.ping(b"");
        });
    }
}

impl StreamHandler<Result<ws::Message, ws::ProtocolError>> for WsSession {
    fn handle(&mut self, msg: Result<ws::Message, ws::ProtocolError>, ctx: &mut Self::Context) {
        match msg {
            Ok(ws::Message::Ping(msg)) => {
                self.hb = Instant::now();
                ctx.pong(&msg);
            }
            Ok(ws::Message::Pong(_)) => {
                self.hb = Instant::now();
            }
            Ok(ws::Message::Text(_)) => {}
            Ok(ws::Message::Binary(_)) => {}
            Ok(ws::Message::Close(reason)) => {
                ctx.close(reason);
                ctx.stop();
            }
            _ => ctx.stop(),
        }
    }
}

#[derive(Message, Clone)]
#[rtype(result = "()")]
pub struct WsMessage(pub String);

impl Handler<WsMessage> for WsSession {
    type Result = ();

    fn handle(&mut self, msg: WsMessage, ctx: &mut Self::Context) {
        ctx.text(msg.0);
    }
}

pub struct Broadcaster {
    pub sessions: DashMap<usize, Recipient<WsMessage>>,
}

impl Default for Broadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl Broadcaster {
    pub fn new() -> Self {
        Self {
            sessions: DashMap::new(),
        }
    }
}

impl MessageBroadcaster for Broadcaster {
    fn broadcast(&self, msg: String) {
        for entry in self.sessions.iter() {
            entry.value().do_send(WsMessage(msg.clone()));
        }
    }
}

pub async fn ws_route(
    req: HttpRequest,
    stream: web::Payload,
    broadcaster: web::Data<Arc<Broadcaster>>,
) -> Result<HttpResponse, Error> {
    if !is_authorized(&req) {
        return Err(actix_web::error::ErrorForbidden("Access Denied"));
    }
    
    use std::sync::atomic::{AtomicUsize, Ordering};
    static NEXT_ID: AtomicUsize = AtomicUsize::new(1);
    let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);

    ws::start(
        WsSession {
            id,
            hb: Instant::now(),
            broadcaster: broadcaster.get_ref().clone(),
        },
        &req,
        stream,
    )
}
