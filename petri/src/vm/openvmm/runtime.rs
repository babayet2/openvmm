// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Methods to interact with a running [`PetriVmOpenVmm`].

use super::PetriVmResourcesOpenVmm;
use crate::OpenHclServicingFlags;
use crate::PetriVmRuntime;
use crate::ShutdownKind;
use crate::openhcl_diag::OpenHclDiagHandler;
use crate::worker::Worker;
use anyhow::Context;
use async_trait::async_trait;
use diag_client::kmsg_stream::KmsgStream;
use futures::FutureExt;
use futures_concurrency::future::Race;
use get_resources::ged::FirmwareEvent;
use hvlite_defs::rpc::PulseSaveRestoreError;
use hyperv_ic_resources::shutdown::ShutdownRpc;
use mesh::CancelContext;
use mesh::Receiver;
use mesh::RecvError;
use mesh::rpc::RpcError;
use mesh::rpc::RpcSend;
use mesh_process::Mesh;
use pal_async::DefaultDriver;
use pal_async::socket::PolledSocket;
use pal_async::task::Task;
use petri_artifacts_core::ResolvedArtifact;
use pipette_client::PipetteClient;
use std::future::Future;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use unix_socket::UnixListener;
use vmm_core_defs::HaltReason;
use vtl2_settings_proto::Vtl2Settings;

/// A running VM that tests can interact with.
// DEVNOTE: Really the PetriVmInner is the actual VM and channels that we interact
// with. This struct exists as a wrapper to provide error handling, such as not
// hanging indefinitely when waiting on certain channels if the VM crashes.
pub struct PetriVmOpenVmm {
    inner: PetriVmInner,
    halt: PetriVmHaltReceiver,
}

#[async_trait]
impl PetriVmRuntime for PetriVmOpenVmm {
    async fn teardown(self) -> anyhow::Result<()> {
        tracing::info!("cancelling watchdogs");
        futures::future::join_all(self.inner.watchdog_tasks.into_iter().map(|t| t.cancel())).await;

        tracing::info!("Cancelled watchdogs, waiting for worker");
        let worker = Arc::into_inner(self.inner.worker)
            .expect("Watchdog task was cancelled, we should be the only ref left");
        worker.shutdown().await?;

        tracing::info!("Worker quit, waiting for mesh");
        self.inner.mesh.shutdown().await;

        tracing::info!("Mesh shutdown, waiting for logging tasks");
        for t in self.inner.resources.log_stream_tasks {
            t.await?;
        }

        Ok(())
    }

    async fn wait_for_halt(&mut self) -> anyhow::Result<HaltReason> {
        let halt_reason = if let Some(already) = self.halt.already_received.take() {
            already.map_err(anyhow::Error::from)
        } else {
            self.halt
                .halt_notif
                .recv()
                .await
                .context("Failed to get halt reason")
        }?;

        tracing::info!(?halt_reason, "Got halt reason");
        Ok(halt_reason)
    }

    async fn wait_for_agent(&mut self, set_high_vtl: bool) -> anyhow::Result<PipetteClient> {
        Self::wait_for_agent(self, set_high_vtl).await
    }

    fn openhcl_diag(&self) -> Option<&OpenHclDiagHandler> {
        self.inner.resources.openhcl_diag_handler.as_ref()
    }

    async fn wait_for_successful_boot_event(&mut self) -> anyhow::Result<()> {
        Self::wait_for_successful_boot_event(self).await
    }

    async fn wait_for_boot_event(&mut self) -> anyhow::Result<FirmwareEvent> {
        Self::wait_for_boot_event(self).await
    }

    async fn wait_for_enlightened_shutdown_ready(&mut self) -> anyhow::Result<()> {
        Self::wait_for_enlightened_shutdown_ready(self)
            .await
            .map(|_| ())
    }

    async fn send_enlightened_shutdown(&mut self, kind: ShutdownKind) -> anyhow::Result<()> {
        Self::send_enlightened_shutdown(self, kind).await
    }

    async fn restart_openhcl(
        &mut self,
        new_openhcl: &ResolvedArtifact,
        flags: OpenHclServicingFlags,
    ) -> anyhow::Result<()> {
        Self::restart_openhcl(self, new_openhcl, flags).await
    }
}

pub(super) struct PetriVmInner {
    pub(super) resources: PetriVmResourcesOpenVmm,
    pub(super) mesh: Mesh,
    pub(super) worker: Arc<Worker>,
    pub(super) watchdog_tasks: Vec<Task<()>>,
}

struct PetriVmHaltReceiver {
    halt_notif: Receiver<HaltReason>,
    already_received: Option<Result<HaltReason, RecvError>>,
}

// Wrap a PetriVmInner function in [`PetriVmOpenVmm::wait_for_halt_or_internal`] to
// provide better error handling.
macro_rules! petri_vm_fn {
    ($(#[$($attrss:tt)*])* $vis:vis async fn $fn_name:ident (&mut self $(,$arg:ident: $ty:ty)*) $(-> $ret:ty)?) => {
        $(#[$($attrss)*])*
        $vis async fn $fn_name(&mut self, $($arg:$ty,)*) $(-> $ret)? {
            Self::wait_for_halt_or_internal(&mut self.halt, self.inner.$fn_name($($arg,)*)).await
        }
    };
}

// TODO: Add all runtime functions that are not backend specific
// to the `PetriVmRuntime` trait
impl PetriVmOpenVmm {
    pub(super) fn new(inner: PetriVmInner, halt_notif: Receiver<HaltReason>) -> Self {
        Self {
            inner,
            halt: PetriVmHaltReceiver {
                halt_notif,
                already_received: None,
            },
        }
    }

    /// Get the path to the VTL 2 vsock socket, if the VM is configured with OpenHCL.
    pub fn vtl2_vsock_path(&self) -> anyhow::Result<&Path> {
        self.inner
            .resources
            .vtl2_vsock_path
            .as_deref()
            .context("VM is not configured with OpenHCL")
    }

    /// Wait for the VM to halt, returning the reason for the halt,
    /// and cleanly tear down the VM.
    pub async fn wait_for_teardown(mut self) -> anyhow::Result<HaltReason> {
        let halt_reason = self.wait_for_halt().await?;

        self.teardown().await?;

        Ok(halt_reason)
    }

    petri_vm_fn!(
        /// Gets a live core dump of the OpenHCL process specified by 'name' and
        /// writes it to 'path'
        pub async fn openhcl_core_dump(&mut self, name: &str, path: &Path) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Crashes the specified openhcl process
        pub async fn openhcl_crash(&mut self,  name: &str) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Waits for an event emitted by the firmware about its boot status, and
        /// verifies that it is the expected success value.
        ///
        /// * Linux Direct guests do not emit a boot event, so this method immediately returns Ok.
        /// * PCAT guests may not emit an event depending on the PCAT version, this
        /// method is best effort for them.
        pub async fn wait_for_successful_boot_event(&mut self) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Waits for an event emitted by the firmware about its boot status, and
        /// returns that status.
        pub async fn wait_for_boot_event(&mut self) -> anyhow::Result<FirmwareEvent>
    );
    petri_vm_fn!(
        /// Waits for the Hyper-V shutdown IC to be ready, returning a receiver
        /// that will be closed when it is no longer ready.
        pub async fn wait_for_enlightened_shutdown_ready(&mut self) -> anyhow::Result<mesh::OneshotReceiver<()>>
    );
    petri_vm_fn!(
        /// Instruct the guest to shutdown via the Hyper-V shutdown IC.
        pub async fn send_enlightened_shutdown(&mut self, kind: ShutdownKind) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Waits for the KVP IC to be ready, returning a sender that can be used
        /// to send requests to it.
        pub async fn wait_for_kvp(&mut self) -> anyhow::Result<mesh::Sender<hyperv_ic_resources::kvp::KvpRpc>>
    );
    petri_vm_fn!(
        /// Restarts OpenHCL.
        pub async fn restart_openhcl(
            &mut self,
            new_openhcl: &ResolvedArtifact,
            flags: OpenHclServicingFlags
        ) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Resets the hardware state of the VM, simulating a power cycle.
        pub async fn reset(&mut self) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Test that we are able to inspect OpenHCL.
        pub async fn test_inspect_openhcl(&mut self) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Get the kmsg stream from OpenHCL.
        pub async fn kmsg(&mut self) -> anyhow::Result<KmsgStream>
    );
    petri_vm_fn!(
        /// Wait for VTL 2 to report that it is ready to respond to commands.
        /// Will fail if the VM is not running OpenHCL.
        ///
        /// This should only be necessary if you're doing something manual. All
        /// Petri-provided methods will wait for VTL 2 to be ready automatically.
        pub async fn wait_for_vtl2_ready(&mut self) -> anyhow::Result<()>
    );
    petri_vm_fn!(
        /// Wait for a connection from a pipette agent
        pub async fn wait_for_agent(&mut self, set_high_vtl: bool) -> anyhow::Result<PipetteClient>
    );
    petri_vm_fn!(
        /// Modifies OpenHCL VTL2 settings.
        pub async fn modify_vtl2_settings(&mut self, f: impl FnOnce(&mut Vtl2Settings)) -> anyhow::Result<()>
    );

    petri_vm_fn!(pub(crate) async fn resume(&mut self) -> anyhow::Result<()>);
    petri_vm_fn!(pub(crate) async fn verify_save_restore(&mut self) -> anyhow::Result<()>);
    petri_vm_fn!(pub(crate) async fn launch_linux_direct_pipette(&mut self) -> anyhow::Result<()>);

    /// Wrap the provided future in a race with the worker process's halt
    /// notification channel. This is useful for preventing a future from
    /// waiting indefinitely if the VM dies for any reason. If the worker
    /// process crashes the halt notification channel will return an error, and
    /// if the VM halts for any other reason the future will complete with that
    /// reason.
    pub async fn wait_for_halt_or<T, F: Future<Output = anyhow::Result<T>>>(
        &mut self,
        future: F,
    ) -> anyhow::Result<T> {
        Self::wait_for_halt_or_internal(&mut self.halt, future).await
    }

    async fn wait_for_halt_or_internal<T, F: Future<Output = anyhow::Result<T>>>(
        halt: &mut PetriVmHaltReceiver,
        future: F,
    ) -> anyhow::Result<T> {
        let future = &mut std::pin::pin!(future);
        enum Either<T> {
            Future(anyhow::Result<T>),
            Halt(Result<HaltReason, RecvError>),
        }
        let res = (
            future.map(Either::Future),
            halt.halt_notif.recv().map(Either::Halt),
        )
            .race()
            .await;

        match res {
            Either::Future(Ok(success)) => Ok(success),
            Either::Future(Err(e)) => {
                tracing::warn!(
                    ?e,
                    "Future returned with an error, sleeping for 5 seconds to let outstanding work finish"
                );
                let mut c = CancelContext::new().with_timeout(Duration::from_secs(5));
                c.cancelled().await;
                Err(e)
            }
            Either::Halt(halt_result) => {
                tracing::warn!(
                    halt_result = format_args!("{:x?}", halt_result),
                    "Halt channel returned while waiting for other future, sleeping for 5 seconds to let outstanding work finish"
                );
                let mut c = CancelContext::new().with_timeout(Duration::from_secs(5));
                let try_again = c.until_cancelled(future).await;

                match try_again {
                    Ok(fut_result) => {
                        halt.already_received = Some(halt_result);
                        if let Err(e) = &fut_result {
                            tracing::warn!(
                                ?e,
                                "Future returned with an error, sleeping for 5 seconds to let outstanding work finish"
                            );
                            let mut c = CancelContext::new().with_timeout(Duration::from_secs(5));
                            c.cancelled().await;
                        }
                        fut_result
                    }
                    Err(_cancel) => match halt_result {
                        Ok(halt_reason) => Err(anyhow::anyhow!("VM halted: {:x?}", halt_reason)),
                        Err(e) => Err(e).context("VM disappeared"),
                    },
                }
            }
        }
    }
}

impl PetriVmInner {
    async fn openhcl_core_dump(&self, name: &str, path: &Path) -> anyhow::Result<()> {
        self.openhcl_diag()?.core_dump(name, path).await
    }

    async fn openhcl_crash(&self, name: &str) -> anyhow::Result<()> {
        self.openhcl_diag()?.crash(name).await
    }

    async fn wait_for_successful_boot_event(&mut self) -> anyhow::Result<()> {
        if let Some(expected_event) = self.resources.expected_boot_event {
            let event = self.wait_for_boot_event().await?;

            anyhow::ensure!(
                event == expected_event,
                "Did not receive expected successful boot event"
            );
        } else {
            tracing::warn!("Configured firmware does not emit a boot event, skipping");
        }

        Ok(())
    }

    async fn wait_for_boot_event(&mut self) -> anyhow::Result<FirmwareEvent> {
        self.resources
            .firmware_event_recv
            .recv()
            .await
            .context("Failed to get firmware boot event")
    }

    async fn wait_for_enlightened_shutdown_ready(
        &mut self,
    ) -> anyhow::Result<mesh::OneshotReceiver<()>> {
        tracing::info!("Waiting for shutdown ic ready");
        let recv = self
            .resources
            .shutdown_ic_send
            .call(ShutdownRpc::WaitReady, ())
            .await?;

        Ok(recv)
    }

    async fn send_enlightened_shutdown(&mut self, kind: ShutdownKind) -> anyhow::Result<()> {
        tracing::info!("Sending shutdown command");
        let shutdown_result = self
            .resources
            .shutdown_ic_send
            .call(
                ShutdownRpc::Shutdown,
                hyperv_ic_resources::shutdown::ShutdownParams {
                    shutdown_type: match kind {
                        ShutdownKind::Shutdown => {
                            hyperv_ic_resources::shutdown::ShutdownType::PowerOff
                        }
                        ShutdownKind::Reboot => hyperv_ic_resources::shutdown::ShutdownType::Reboot,
                    },
                    force: false,
                },
            )
            .await?;

        tracing::info!(?shutdown_result, "Shutdown sent");
        anyhow::ensure!(
            shutdown_result == hyperv_ic_resources::shutdown::ShutdownResult::Ok,
            "Got non-Ok shutdown response"
        );

        Ok(())
    }

    async fn wait_for_kvp(
        &mut self,
    ) -> anyhow::Result<mesh::Sender<hyperv_ic_resources::kvp::KvpRpc>> {
        tracing::info!("Waiting for KVP IC");
        let (send, _) = self
            .resources
            .kvp_ic_send
            .call_failable(hyperv_ic_resources::kvp::KvpConnectRpc::WaitForGuest, ())
            .await
            .context("failed to connect to KVP IC")?;

        Ok(send)
    }

    async fn restart_openhcl(
        &self,
        new_openhcl: &ResolvedArtifact,
        flags: OpenHclServicingFlags,
    ) -> anyhow::Result<()> {
        let ged_send = self
            .resources
            .ged_send
            .as_ref()
            .context("openhcl not configured")?;

        let igvm_file = fs_err::File::open(new_openhcl).context("failed to open igvm file")?;
        self.worker
            .restart_openhcl(ged_send, flags, igvm_file.into())
            .await
    }

    async fn modify_vtl2_settings(
        &mut self,
        f: impl FnOnce(&mut Vtl2Settings),
    ) -> anyhow::Result<()> {
        f(self.resources.vtl2_settings.as_mut().unwrap());

        let ged_send = self
            .resources
            .ged_send
            .as_ref()
            .context("openhcl not configured")?;

        ged_send
            .call_failable(
                get_resources::ged::GuestEmulationRequest::ModifyVtl2Settings,
                prost::Message::encode_to_vec(self.resources.vtl2_settings.as_ref().unwrap()),
            )
            .await?;

        Ok(())
    }

    async fn reset(&mut self) -> anyhow::Result<()> {
        tracing::info!("Resetting VM");
        self.worker.reset().await?;
        // On linux direct pipette won't auto start, start it over serial
        if let Some(agent) = self.resources.linux_direct_serial_agent.as_mut() {
            agent.reset();

            if self
                .resources
                .agent_image
                .as_ref()
                .is_some_and(|x| x.contains_pipette())
            {
                self.launch_linux_direct_pipette().await?;
            }
        }
        Ok(())
    }

    async fn test_inspect_openhcl(&self) -> anyhow::Result<()> {
        self.openhcl_diag()?.test_inspect().await
    }

    async fn kmsg(&self) -> anyhow::Result<KmsgStream> {
        self.openhcl_diag()?.kmsg().await
    }

    async fn wait_for_vtl2_ready(&mut self) -> anyhow::Result<()> {
        self.openhcl_diag()?.wait_for_vtl2().await
    }

    async fn wait_for_agent(&mut self, set_high_vtl: bool) -> anyhow::Result<PipetteClient> {
        Self::wait_for_agent_core(
            &self.resources.driver,
            if set_high_vtl {
                self.resources
                    .vtl2_pipette_listener
                    .as_mut()
                    .context("VM is not configured with VTL 2")?
            } else {
                &mut self.resources.pipette_listener
            },
            &self.resources.output_dir,
        )
        .await
    }

    async fn wait_for_agent_core(
        driver: &DefaultDriver,
        listener: &mut PolledSocket<UnixListener>,
        output_dir: &Path,
    ) -> anyhow::Result<PipetteClient> {
        // Wait for the pipette connection.
        tracing::info!("listening for pipette connection");
        let (conn, _) = listener
            .accept()
            .await
            .context("failed to accept pipette connection")?;

        tracing::info!("handshaking with pipette");
        let client = PipetteClient::new(&driver, PolledSocket::new(driver, conn)?, output_dir)
            .await
            .context("failed to connect to pipette");

        tracing::info!("completed pipette handshake");
        client
    }

    async fn resume(&self) -> anyhow::Result<()> {
        self.worker.resume().await?;
        Ok(())
    }

    async fn verify_save_restore(&self) -> anyhow::Result<()> {
        for i in 0..2 {
            let result = self.worker.pulse_save_restore().await;
            match result {
                Ok(()) => {}
                Err(RpcError::Channel(err)) => return Err(err.into()),
                Err(RpcError::Call(PulseSaveRestoreError::ResetNotSupported)) => {
                    tracing::warn!("Reset not supported, could not test save + restore.");
                    break;
                }
                Err(RpcError::Call(PulseSaveRestoreError::Other(err))) => {
                    return Err(anyhow::Error::from(err))
                        .context(format!("Save + restore {i} failed."));
                }
            }
        }

        Ok(())
    }

    async fn launch_linux_direct_pipette(&mut self) -> anyhow::Result<()> {
        // Start pipette through serial on linux direct.
        self.resources
            .linux_direct_serial_agent
            .as_mut()
            .unwrap()
            .run_command("mkdir /cidata && mount LABEL=cidata /cidata && sh -c '/cidata/pipette &'")
            .await?;
        Ok(())
    }

    fn openhcl_diag(&self) -> anyhow::Result<&OpenHclDiagHandler> {
        if let Some(ohd) = &self.resources.openhcl_diag_handler {
            Ok(ohd)
        } else {
            anyhow::bail!("VM is not configured with OpenHCL")
        }
    }
}
