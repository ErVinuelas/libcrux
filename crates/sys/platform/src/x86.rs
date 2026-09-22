//! Obtain particular CPU features for x86/x86_64

#![allow(non_upper_case_globals)]

#[cfg(target_arch = "x86")]
use core::arch::x86::{__cpuid, __cpuid_count, CpuidResult};
#[cfg(target_arch = "x86_64")]
use core::arch::x86_64::{__cpuid, __cpuid_count, CpuidResult};
use core::sync::atomic::{AtomicU8, Ordering};

#[allow(non_camel_case_types)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(super) enum Feature {
    mmx,
    sse,
    sse2,
    sse3,
    pclmulqdq,
    ssse3,
    fma,
    movbe,
    sse4_1,
    sse4_2,
    popcnt,
    aes,
    xsave,
    osxsave,
    avx,
    rdrand,
    sgx,
    bmi1,
    avx2,
    bmi2,
    avx512f,
    avx512dq,
    rdseed,
    adx,
    avx512ifma,
    avx512pf,
    avx512er,
    avx512cd,
    sha,
    avx512bw,
    avx512vl,
}

/// Check hardware [`Feature`] support.
pub(super) fn supported(feature: Feature) -> bool {
    init();
    let cpu_id_0 = unsafe { CPU_ID[0] };
    let cpu_id_1 = unsafe { CPU_ID[1] };
    match feature {
        Feature::mmx => cpu_id_0.edx & (1 << 23) != 0,
        Feature::sse => cpu_id_0.edx & (1 << 25) != 0,
        Feature::sse2 => cpu_id_0.edx & (1 << 26) != 0,
        Feature::sse3 => cpu_id_0.ecx & (1 << 0) != 0,
        Feature::pclmulqdq => cpu_id_0.ecx & (1 << 1) != 0,
        Feature::ssse3 => cpu_id_0.ecx & (1 << 9) != 0,
        Feature::fma => cpu_id_0.ecx & (1 << 12) != 0,
        Feature::movbe => cpu_id_0.ecx & (1 << 22) != 0,
        Feature::sse4_1 => cpu_id_0.ecx & (1 << 19) != 0,
        Feature::sse4_2 => cpu_id_0.ecx & (1 << 20) != 0,
        Feature::popcnt => cpu_id_0.ecx & (1 << 23) != 0,
        Feature::aes => cpu_id_0.ecx & (1 << 25) != 0,
        Feature::xsave => cpu_id_0.ecx & (1 << 26) != 0,
        Feature::osxsave => cpu_id_0.ecx & (1 << 27) != 0,
        Feature::avx => {
            cpu_id_0.ecx & (1 << 28) != 0
                && supported(Feature::xsave)
                && supported(Feature::osxsave)
        }
        Feature::rdrand => cpu_id_0.ecx & (1 << 30) != 0,
        Feature::sgx => cpu_id_1.ebx & (1 << 2) != 0,
        Feature::bmi1 => cpu_id_1.ebx & (1 << 3) != 0,
        Feature::avx2 => {
            cpu_id_1.ebx & (1 << 5) != 0
                && supported(Feature::bmi1)
                && supported(Feature::bmi2)
                && supported(Feature::fma)
                && supported(Feature::movbe)
        }
        Feature::bmi2 => cpu_id_1.ebx & (1 << 8) != 0,
        Feature::avx512f => cpu_id_1.ebx & (1 << 16) != 0,
        Feature::avx512dq => cpu_id_1.ebx & (1 << 17) != 0,
        Feature::rdseed => cpu_id_1.ebx & (1 << 18) != 0,
        Feature::adx => cpu_id_1.ebx & (1 << 19) != 0,
        Feature::avx512ifma => cpu_id_1.ebx & (1 << 21) != 0,
        Feature::avx512pf => cpu_id_1.ebx & (1 << 26) != 0,
        Feature::avx512er => cpu_id_1.ebx & (1 << 27) != 0,
        Feature::avx512cd => cpu_id_1.ebx & (1 << 28) != 0,
        Feature::sha => cpu_id_1.ebx & (1 << 29) != 0,
        Feature::avx512bw => cpu_id_1.ebx & (1 << 30) != 0,
        Feature::avx512vl => cpu_id_1.ebx & (1 << 31) != 0,
    }
}

// Guarded by INITIALIZED; always use load-acquire and store-release access to guarantee atomicity.
static mut CPU_ID: [CpuidResult; 2] = [
    CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    },
    CpuidResult {
        eax: 0,
        ebx: 0,
        ecx: 0,
        edx: 0,
    },
];

/// `INITIALIZED` has not been set yet; `CPU_ID` contains no valid data.
const UNINIT: u8 = 0;
/// One thread won the compare_exchange race and is currently writing `CPU_ID`.
const IN_PROGRESS: u8 = 1;
/// `CPU_ID` has been fully written and is safe to read.
const DONE: u8 = 2;

/// Guards access to `CPU_ID`.
///
/// Transitions: `UNINIT` → `IN_PROGRESS` (via compare_exchange, exactly one thread) →
/// `DONE` (store-release, makes `CPU_ID` visible to all subsequent load-acquire readers).
static INITIALIZED: AtomicU8 = AtomicU8::new(UNINIT);

/// Initialize CPU detection.
#[inline(always)]
pub(super) fn init() {
    // Implementation partially based on:
    // https://github.com/rust-lang/rust/blob/e5b95097d9a14bdec7cd9101dde67ee3aad2578a/library/std_detect/src/detect/os/x86.rs#L27

    // No cpuid support on Intel SGX
    if cfg!(target_env = "sgx") {
        // We can save ourselves the store of DONE to INITIALIZED here,
        // on this target every caller just immediately returns, and the
        // bit tests for the features will return false.
        return;
    }

    if INITIALIZED.load(Ordering::Acquire) == DONE {
        return;
    }

    #[inline(never)]
    unsafe fn cpuid(leaf: u32) -> CpuidResult {
        __cpuid(leaf)
    }

    #[inline(never)]
    unsafe fn cpuid_count(leaf: u32, sub_leaf: u32) -> CpuidResult {
        __cpuid_count(leaf, sub_leaf)
    }

    let CpuidResult {
        eax: max_basic_leaf,
        ..
    } = unsafe { cpuid(0) };
    if max_basic_leaf < 1 {
        // Earlier Intel 486, CPUID not implemented
        return;
    }

    // Use compare_exchange to ensure only one thread writes CPU_ID.
    // Other threads spin-wait until initialization is complete.
    if INITIALIZED
        .compare_exchange(UNINIT, IN_PROGRESS, Ordering::AcqRel, Ordering::Acquire)
        .is_ok()
    {
        // EAX = 1, ECX = 0: Queries "Processor Info and Feature Bits";
        // Contains information about most x86 features.
        let basic_features = unsafe { cpuid(1) };
        // EAX = 7: Queries "Extended Features";
        // Contains information about bmi,bmi2, and avx2 support.
        let extended_features = if max_basic_leaf >= 7 {
            unsafe { cpuid_count(7, 0) }
        } else {
            // No extended features available.
            CpuidResult {
                eax: 0,
                ebx: 0,
                ecx: 0,
                edx: 0,
            }
        };
        // SAFETY: Access to CPU_ID is guarded by the CAS. Only ever one thread
        // can be IN_PROGRESS and write to CPU_ID.
        unsafe {
            CPU_ID = [basic_features, extended_features];
        };
        INITIALIZED.store(DONE, Ordering::Release);
    } else {
        // Spin-wait for the initializing thread to finish.
        while INITIALIZED.load(Ordering::Acquire) != DONE {
            core::hint::spin_loop();
        }
    }
}
