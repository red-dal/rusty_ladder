use hyper::{
	service::{make_service_fn, service_fn},
	Body, Request, Response, Server,
};
use log::info;
use std::{convert::Infallible, error::Error as StdErr, net::SocketAddr};

async fn serve_something(_req: Request<Body>) -> Result<Response<Body>, Infallible> {
	let something = super::SERVED_DATA.as_str();
	info!(
		"Serving HTTP request with {} bytes of something",
		something.len()
	);
	Ok(Response::new(something.into()))
}

pub async fn serve(addr: SocketAddr) -> Result<(), Box<dyn StdErr + Send + Sync>> {
	info!("Running HTTP server on {}", addr);
	let make_service =
		make_service_fn(|_conn| async { Ok::<_, Infallible>(service_fn(serve_something)) });
	Server::bind(&addr).serve(make_service).await?;
	Ok(())
}
