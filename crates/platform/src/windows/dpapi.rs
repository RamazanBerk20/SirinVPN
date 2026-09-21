//! Native DPAPI only. Neither audit flags nor plaintext fallback are supported.
use std::{io, ptr};
use windows_sys::Win32::{
    Foundation::LocalFree,
    Security::Cryptography::{
        CRYPT_INTEGER_BLOB, CRYPTPROTECT_LOCAL_MACHINE, CRYPTPROTECT_UI_FORBIDDEN,
        CryptProtectData, CryptUnprotectData,
    },
};
use zeroize::{Zeroize, Zeroizing};

const MAGIC: &[u8] = b"SIRINVPN-DPAPI\x01";
const MAX_BYTES: usize = 1024 * 1024;

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum Scope {
    User = 0,
    Machine = 1,
}

struct Output(CRYPT_INTEGER_BLOB);
impl Drop for Output {
    fn drop(&mut self) {
        if !self.0.pbData.is_null() {
            // DPAPI owns this initialized allocation until LocalFree.
            unsafe {
                std::slice::from_raw_parts_mut(self.0.pbData, self.0.cbData as usize).zeroize();
                LocalFree(self.0.pbData.cast());
            }
        }
    }
}

fn entropy(binding: &str, scope: Scope) -> io::Result<Vec<u8>> {
    if binding.is_empty() || binding.len() > 512 || binding.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid DPAPI state binding",
        ));
    }
    let mut bytes = b"SirinVPN platform state v1\0".to_vec();
    bytes.push(scope as u8);
    bytes.extend_from_slice(binding.as_bytes());
    Ok(bytes)
}

pub fn protect(plaintext: &[u8], scope: Scope, binding: &str) -> io::Result<Vec<u8>> {
    if plaintext.is_empty() || plaintext.len() > MAX_BYTES {
        return Err(invalid());
    }
    let entropy = entropy(binding, scope)?;
    let input = blob(plaintext);
    let additional = blob(&entropy);
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    });
    let flags = CRYPTPROTECT_UI_FORBIDDEN
        | if scope == Scope::Machine {
            CRYPTPROTECT_LOCAL_MACHINE
        } else {
            0
        };
    // All borrowed buffers outlive the synchronous API call; no description/audit output.
    if unsafe {
        CryptProtectData(
            &input,
            ptr::null(),
            &additional,
            ptr::null(),
            ptr::null(),
            flags,
            &mut output.0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if output.0.pbData.is_null() || output.0.cbData as usize > MAX_BYTES + 4096 {
        return Err(invalid());
    }
    let mut envelope = MAGIC.to_vec();
    envelope.push(scope as u8);
    envelope.extend_from_slice(unsafe {
        std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize)
    });
    Ok(envelope)
}

pub fn unprotect(envelope: &[u8], scope: Scope, binding: &str) -> io::Result<Zeroizing<Vec<u8>>> {
    if envelope.len() <= MAGIC.len() + 1
        || envelope.len() > MAX_BYTES + 8192
        || !envelope.starts_with(MAGIC)
        || envelope[MAGIC.len()] != scope as u8
    {
        return Err(invalid());
    }
    let entropy = entropy(binding, scope)?;
    let input = blob(&envelope[MAGIC.len() + 1..]);
    let additional = blob(&entropy);
    let mut output = Output(CRYPT_INTEGER_BLOB {
        cbData: 0,
        pbData: ptr::null_mut(),
    });
    if unsafe {
        CryptUnprotectData(
            &input,
            ptr::null_mut(),
            &additional,
            ptr::null(),
            ptr::null(),
            CRYPTPROTECT_UI_FORBIDDEN,
            &mut output.0,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if output.0.pbData.is_null() || output.0.cbData == 0 || output.0.cbData as usize > MAX_BYTES {
        return Err(invalid());
    }
    Ok(Zeroizing::new(
        unsafe { std::slice::from_raw_parts(output.0.pbData, output.0.cbData as usize) }.to_vec(),
    ))
}

fn blob(bytes: &[u8]) -> CRYPT_INTEGER_BLOB {
    CRYPT_INTEGER_BLOB {
        cbData: bytes.len() as u32,
        pbData: bytes.as_ptr().cast_mut(),
    }
}
fn invalid() -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        "invalid encrypted Windows state",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dpapi_requires_the_same_scope_binding_and_intact_ciphertext() {
        let encrypted = protect(b"local private identity", Scope::User, "test-identity").unwrap();
        assert_eq!(
            unprotect(&encrypted, Scope::User, "test-identity")
                .unwrap()
                .as_slice(),
            b"local private identity"
        );
        assert!(unprotect(&encrypted, Scope::User, "another-identity").is_err());
        assert!(unprotect(&encrypted, Scope::Machine, "test-identity").is_err());
        let mut tampered = encrypted;
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(unprotect(&tampered, Scope::User, "test-identity").is_err());
    }
}
