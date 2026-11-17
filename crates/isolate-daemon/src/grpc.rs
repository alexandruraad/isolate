// SPDX-License-Identifier: Apache-2.0
//! gRPC server skeleton — will be filled out once isolate-proto (tonic stubs)
//! are generated from proto/isolate.proto.
//!
//! For now this module exports a `serve` function that starts a placeholder
//! tonic server so the binary compiles and can be wired up incrementally.

use anyhow::Result;
use std::net::SocketAddr;
use tracing::info;

/// Start the gRPC server on `addr`.
///
/// # Phase 1
/// Returns immediately after logging; the real tonic service implementations
/// live in `crates/isolate-proto/src/service/` and will be plugged in once
/// the protobuf stubs are generated.
pub async fn serve(addr: SocketAddr) -> Result<()> {
    info!(addr = %addr, "gRPC server stub listening (full implementation pending proto codegen)");

    // TODO: Replace with real tonic Router once isolate-proto is wired:
    //
    //   use isolate_proto::isolate_service_server::IsolateServiceServer;
    //   use crate::grpc_impl::IsolateServiceImpl;
    //
    //   tonic::transport::Server::builder()
    //       .add_service(IsolateServiceServer::new(IsolateServiceImpl::new(...)))
    //       .serve(addr)
    //       .await?;

    // Keep the task alive (simulate a long-running server)
    tokio::signal::ctrl_c().await?;
    Ok(())
}
