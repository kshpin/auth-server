use std::{
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use jsonwebtoken::{decode, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation};
use lazy_static::lazy_static;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use warp::{http::Response, Filter, Reply};

// 24 hours
const TOKEN_LIFETIME: usize = 60 * 60 * 24;

lazy_static! {
    static ref ENCODING_KEY: EncodingKey =
        EncodingKey::from_rsa_pem(include_bytes!("../rsa_keys/private.pem"))
            .expect("RSA encoding key");
    static ref DECODING_KEY: DecodingKey<'static> =
        DecodingKey::from_rsa_pem(include_bytes!("../rsa_keys/public.pem"))
            .expect("RSA decoding key");
    static ref PUBLIC_KEY: &'static str = include_str!("../rsa_keys/public.pem");
}

#[derive(Debug, Serialize, Deserialize)]
struct Claims {
    sub: String,
    nbf: usize,
    exp: usize,
}

struct Averager {
    count: u128,
    avg: u128,
}

impl Default for Averager {
    fn default() -> Self {
        Self {
            count: 0u128,
            avg: 0u128,
        }
    }
}

impl Averager {
    fn insert(&mut self, val: u128) {
        self.avg = (self.avg * self.count + val) / (self.count + 1);
        self.count += 1;
    }
}

struct Stats {
    encoding_averager: Averager,
    decoding_averager: Averager,
}

impl Default for Stats {
    fn default() -> Self {
        Self {
            encoding_averager: Averager::default(),
            decoding_averager: Averager::default(),
        }
    }
}

impl Stats {
    fn insert_encoding_duration(&mut self, val: u128) {
        self.encoding_averager.insert(val);
    }

    fn insert_decoding_duration(&mut self, val: u128) {
        self.decoding_averager.insert(val);
    }

    fn get_report(&self) -> String {
        format!(
            "Successful encoding requests: {}\nAverage encoding duration:    {}ns\n\nSuccessful decoding requests: {}\nAverage decoding duration:    {}ns",
            self.encoding_averager.count,
            self.encoding_averager.avg,
            self.decoding_averager.count,
            self.decoding_averager.avg
        )
    }
}

async fn handle_auth(username: String, stats: Arc<RwLock<Stats>>) -> impl Reply {
    let header = Header::new(Algorithm::RS256);

    if let Ok(duration_since_epoch) = SystemTime::now().duration_since(UNIX_EPOCH) {
        let ts_cur = duration_since_epoch.as_secs() as usize;

        let ts_exp = ts_cur + TOKEN_LIFETIME;

        let claims = Claims {
            sub: username,
            nbf: ts_cur,
            exp: ts_exp,
        };

        let start_time = SystemTime::now();
        let encoding_res = encode(&header, &claims, &ENCODING_KEY);
        let duration_res = SystemTime::now().duration_since(start_time);

        if let Ok(token) = encoding_res {
            if let Ok(encoding_duration) = duration_res {
                stats
                    .write()
                    .await
                    .insert_encoding_duration(encoding_duration.as_nanos());

                Response::builder()
                    .header(
                        "Set-Cookie",
                        format!("token={}; Secure; HttpOnly; Path=/", token),
                    )
                    .body(PUBLIC_KEY.to_owned())
                    .expect("built response")
            } else {
                // couldn't get the encoding duration
                Response::builder()
                    .status(500)
                    .body("".to_owned())
                    .expect("built response")
            }
        } else {
            // couldn't encode
            Response::builder()
                .status(500)
                .body("".to_owned())
                .expect("built response")
        }
    } else {
        // couldn't get the current unix timestamp
        Response::builder()
            .status(500)
            .body("".to_owned())
            .expect("built response")
    }
}

async fn handle_verify(token: String, stats: Arc<RwLock<Stats>>) -> impl Reply {
    let validation = Validation::new(Algorithm::RS256);

    let start_time = SystemTime::now();
    let decoding_res = decode::<Claims>(&token, &DECODING_KEY, &validation);
    let duration_res = SystemTime::now().duration_since(start_time);

    if let Ok(decoded) = decoding_res {
        if let Ok(decoding_duration) = duration_res {
            stats
                .write()
                .await
                .insert_decoding_duration(decoding_duration.as_nanos());

            Response::builder()
                .status(200)
                .header("Content-Type", "text/plain")
                .body(decoded.claims.sub)
                .expect("built response")
        } else {
            // couldn't get the decoding duration
            Response::builder()
                .status(500)
                .body("".to_owned())
                .expect("built response")
        }
    } else {
        // couldn't decode
        Response::builder()
            .status(498)
            .body("Token is expired or invalid".to_owned())
            .expect("built response")
    }
}

async fn handle_stats(stats: Arc<RwLock<Stats>>) -> impl Reply {
    stats.read().await.get_report()
}

#[tokio::main]
async fn main() {
    let stats = Arc::new(RwLock::new(Stats::default()));

    // match "/auth/[username]"
    let stats_clone = stats.clone();
    let auth = warp::path!("auth" / String).then(move |username| {
        let stats_clone_inner = stats_clone.clone();
        async { handle_auth(username, stats_clone_inner).await }
    });

    // match "/verify", and extract cookie "token"
    let stats_clone = stats.clone();
    let verify_with_cookie = warp::path("verify")
        .and(warp::filters::cookie::cookie("token"))
        .then(move |token| {
            let stats_clone_inner = stats_clone.clone();
            async { handle_verify(token, stats_clone_inner).await }
        });

    // match "/verify" without a cookie present (immediate 401)
    let verify_without_cookie = warp::path("verify").map(move || {
        Response::builder()
            .status(401)
            .body("".to_owned())
            .expect("built response")
    });

    // match "/stats"
    let stats_clone = stats.clone();
    let stats = warp::path("stats").then(move || {
        let stats_clone_inner = stats_clone.clone();
        async { handle_stats(stats_clone_inner).await }
    });

    // match "/README.txt"
    let readme = warp::path("README.txt").and(warp::fs::file("./README.txt"));

    // match anything else
    let other = warp::any().map(|| {
        Response::builder()
            .status(404)
            .body("".to_owned())
            .expect("built response")
    });

    let route = auth
        .or(verify_with_cookie)
        .or(verify_without_cookie)
        .or(readme)
        .or(stats)
        .or(other);
    warp::serve(route).run(([127, 0, 0, 1], 3030)).await;
}
