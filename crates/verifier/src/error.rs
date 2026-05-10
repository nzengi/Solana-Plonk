use core::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Error {
    /// Proof bytes did not parse into the expected layout.
    InvalidProofEncoding,
    /// Verifying key bytes did not parse into the expected layout.
    InvalidVkEncoding,
    /// Public input scalar exceeded the BN254 Fr modulus.
    PublicInputOutOfRange,
    /// A syscall returned an error code.
    SyscallFailed { which: &'static str, code: u64 },
    /// The KZG pairing equation did not hold.
    PairingCheckFailed,
    /// Out of compute units mid-verification (heuristic).
    ComputeBudgetExhausted,
    /// Generic protocol/transcript error from the vendored verifier core.
    Protocol(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidProofEncoding      => f.write_str("invalid proof encoding"),
            Error::InvalidVkEncoding         => f.write_str("invalid verifying key encoding"),
            Error::PublicInputOutOfRange     => f.write_str("public input not in Fr"),
            Error::SyscallFailed { which, code } =>
                write!(f, "syscall {which} failed with code {code}"),
            Error::PairingCheckFailed        => f.write_str("pairing check failed"),
            Error::ComputeBudgetExhausted    => f.write_str("compute budget exhausted"),
            Error::Protocol(msg)             => write!(f, "protocol error: {msg}"),
        }
    }
}
