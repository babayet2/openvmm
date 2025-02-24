// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Hypercall architecture-dependent infrastructure.
//!
//! The hypercall ABI for x64 is well documented in the TLFS.

use crate::isolation::IsolationType;
use tdcall::tdcall_hypercall;
use tdcall::Tdcall;
use tdcall::TdcallInput;
use tdcall::TdcallOutput;

unsafe extern "C" {
    /// The hypercall page. The actual hypercall page must be mapped on top of
    /// this page before it is used.
    pub static mut HYPERCALL_PAGE: [u8; 4096];
}

core::arch::global_asm! {
    r#"
.globl HYPERCALL_PAGE
.align 4096
HYPERCALL_PAGE:
    ud2
    .skip 4094, 0xcc
"#,
}

/// Invokes a standard hypercall, or a fast hypercall with at most two input
/// words and zero output words.
///
/// # Safety
/// The caller must ensure the hypercall is safe to issue, and that the
/// input/output pages are not being concurrently used elsewhere. For fast
/// hypercalls, the caller must ensure that there are no output words so that
/// there is no register corruption.
pub unsafe fn invoke_hypercall(
    isolation_type: IsolationType,
    control: hvdef::hypercall::Control,
    input_gpa_or_fast1: u64,
    output_gpa_or_fast2: u64,
) -> hvdef::hypercall::HypercallOutput {
    let output: u64;
    // SAFETY: the caller guarantees the safety of this operation.
    unsafe {
        if isolation_type == IsolationType::Tdx {
            output = invoke_tdcall(control, input_gpa_or_fast1, output_gpa_or_fast2);
        } else {
            core::arch::asm! {
                "call {hypercall_page}",
                hypercall_page = sym HYPERCALL_PAGE,
                inout("rcx") u64::from(control) => _,
                in("rdx") input_gpa_or_fast1,
                in("r8") output_gpa_or_fast2,
                out("rax") output,
            }
        }
    }
    output.into()
}

/// Perform a tdcall instruction with the specified inputs.
fn tdcall(input: TdcallInput) -> TdcallOutput {
    const TD_VMCALL: u64 = 0;

    let rax: u64;
    let rcx;
    let rdx;
    let r8;
    let r10;
    let r11;

    // Since this TDCALL is used only for TDVMCALL based hypercalls,
    // check and make sure that the TDCALL is VMCALL
    assert_eq!(input.leaf.0, TD_VMCALL);

    // SAFETY: Any input registers can be output registers for VMCALL, so make sure
    // they're all inout even if the output isn't used.
    //
    unsafe {
        core::arch::asm! {
            "tdcall",
            inout("rax") input.leaf.0 => rax,
            inout("rcx") input.rcx => rcx,
            inout("rdx") input.rdx => rdx,
            inout("r8") input.r8 => r8,
            inout("r9")  input.r9 => _,
            inout("r10") input.r10 => r10,
            inout("r11") input.r11 => r11,
            inout("r12") input.r12 => _,
            inout("r13") input.r13 => _,
            inout("r14") input.r14 => _,
            inout("r15") input.r15 => _,
        }
    }

    TdcallOutput {
        rax: rax.into(),
        rcx,
        rdx,
        r8,
        r10,
        r11,
    }
}

/// This struct implements tdcall trait and is passed in tacall functions
pub struct TdcallInstruction;

impl Tdcall for TdcallInstruction {
    fn tdcall(&mut self, input: TdcallInput) -> TdcallOutput {
        tdcall(input)
    }
}

fn invoke_tdcall(control: hvdef::hypercall::Control, input: u64, output: u64) -> u64 {
    let status: u64 = 0;

    let _ = tdcall_hypercall(&mut TdcallInstruction, control, input, output);

    status
}
