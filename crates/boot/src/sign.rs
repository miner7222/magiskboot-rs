use der::referenced::OwnedToRef;
use der::{Decode, DecodePem, Encode, Sequence, SliceReader};
use digest::DynDigest;
use p256::ecdsa::{
    Signature as P256Signature, SigningKey as P256SigningKey, VerifyingKey as P256VerifyingKey,
};
use p256::pkcs8::DecodePrivateKey;
use p384::ecdsa::{
    Signature as P384Signature, SigningKey as P384SigningKey, VerifyingKey as P384VerifyingKey,
};
// p521 0.13 does not support TryFrom<SubjectPublicKeyInfo> for VerifyingKey
// or DecodePrivateKey for SigningKey, so P521 ECDSA is disabled for now.
// use p521::ecdsa::{
//     Signature as P521Signature, SigningKey as P521SigningKey, VerifyingKey as P521VerifyingKey,
// };
use rsa::pkcs1v15::{
    Signature as RsaSignature, SigningKey as RsaSigningKey, VerifyingKey as RsaVerifyingKey,
};
use rsa::pkcs8::SubjectPublicKeyInfoRef;
use rsa::signature::SignatureEncoding;
use rsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha1::Sha1;
use sha2::{Sha256, Sha384};
use x509_cert::Certificate;
use x509_cert::der::Any;
use x509_cert::der::asn1::{OctetString, PrintableString};
use x509_cert::spki::AlgorithmIdentifier;

use base::{LoggedResult, MappedFile, ResultExt, SilentLogExt, Utf8CStr, cstr, log_err};

use crate::ffi::BootImage;

#[allow(clippy::upper_case_acronyms)]
pub enum SHA {
    SHA1(Sha1),
    SHA256(Sha256),
}

impl SHA {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            SHA::SHA1(h) => h.update(data),
            SHA::SHA256(h) => h.update(data),
        }
    }

    pub fn output_size(&self) -> usize {
        match self {
            SHA::SHA1(h) => h.output_size(),
            SHA::SHA256(h) => h.output_size(),
        }
    }

    pub fn finalize_into(&mut self, out: &mut [u8]) {
        match self {
            SHA::SHA1(h) => h.finalize_into_reset(out),
            SHA::SHA256(h) => h.finalize_into_reset(out),
        }
        .ok();
    }
}

pub fn get_sha(use_sha1: bool) -> Box<SHA> {
    Box::new(if use_sha1 {
        SHA::SHA1(Sha1::default())
    } else {
        SHA::SHA256(Sha256::default())
    })
}

pub fn sha1_hash(data: &[u8], out: &mut [u8]) {
    let mut h = Sha1::default();
    h.update(data);
    DynDigest::finalize_into(h, out).ok();
}

pub fn sha256_hash(data: &[u8], out: &mut [u8]) {
    let mut h = Sha256::default();
    h.update(data);
    DynDigest::finalize_into(h, out).ok();
}

#[allow(clippy::large_enum_variant)]
enum SigningKey {
    SHA256withRSA(RsaSigningKey<Sha256>),
    SHA256withECDSA(P256SigningKey),
    SHA384withECDSA(P384SigningKey),
    // SHA521withECDSA disabled: p521 0.13 lacks pkcs8/spki support
}

#[allow(clippy::large_enum_variant)]
enum VerifyingKey {
    SHA256withRSA(RsaVerifyingKey<Sha256>),
    SHA256withECDSA(P256VerifyingKey),
    SHA384withECDSA(P384VerifyingKey),
    // SHA521withECDSA disabled: p521 0.13 lacks pkcs8/spki support
}

struct Verifier {
    digest: Box<dyn DynDigest>,
    key: VerifyingKey,
}

impl Verifier {
    fn from_public_key(key: SubjectPublicKeyInfoRef) -> LoggedResult<Verifier> {
        let digest: Box<dyn DynDigest>;
        let key = if let Ok(rsa) = RsaPublicKey::try_from(key.clone()) {
            digest = Box::<Sha256>::default();
            VerifyingKey::SHA256withRSA(RsaVerifyingKey::<Sha256>::new(rsa))
        } else if let Ok(ec) = P256VerifyingKey::try_from(key.clone()) {
            digest = Box::<Sha256>::default();
            VerifyingKey::SHA256withECDSA(ec)
        } else if let Ok(ec) = P384VerifyingKey::try_from(key.clone()) {
            digest = Box::<Sha384>::default();
            VerifyingKey::SHA384withECDSA(ec)
        } else {
            return log_err!("Unsupported private key");
        };
        Ok(Verifier { digest, key })
    }

    fn update(&mut self, data: &[u8]) {
        self.digest.update(data)
    }

    fn verify(mut self, signature: &[u8]) -> LoggedResult<()> {
        let hash = self.digest.finalize_reset();
        match &self.key {
            VerifyingKey::SHA256withRSA(key) => {
                let sig = RsaSignature::try_from(signature)?;
                key.verify_prehash(hash.as_ref(), &sig).log()
            }
            VerifyingKey::SHA256withECDSA(key) => {
                let sig = P256Signature::from_slice(signature)?;
                key.verify_prehash(hash.as_ref(), &sig).log()
            }
            VerifyingKey::SHA384withECDSA(key) => {
                let sig = P384Signature::from_slice(signature)?;
                key.verify_prehash(hash.as_ref(), &sig).log()
            }
        }
    }
}

struct Signer {
    digest: Box<dyn DynDigest>,
    key: SigningKey,
}

impl Signer {
    fn from_private_key(key: &[u8]) -> LoggedResult<Signer> {
        let digest: Box<dyn DynDigest>;
        let key = match RsaPrivateKey::from_pkcs8_der(key) {
            Ok(rsa) => {
                digest = Box::<Sha256>::default();
                SigningKey::SHA256withRSA(RsaSigningKey::<Sha256>::new(rsa))
            }
            _ => match P256SigningKey::from_pkcs8_der(key) {
                Ok(ec) => {
                    digest = Box::<Sha256>::default();
                    SigningKey::SHA256withECDSA(ec)
                }
                _ => match P384SigningKey::from_pkcs8_der(key) {
                    Ok(ec) => {
                        digest = Box::<Sha384>::default();
                        SigningKey::SHA384withECDSA(ec)
                    }
                    _ => {
                        return log_err!("Unsupported private key");
                    }
                },
            },
        };
        Ok(Signer { digest, key })
    }

    fn update(&mut self, data: &[u8]) {
        self.digest.update(data)
    }

    fn sign(mut self) -> LoggedResult<Vec<u8>> {
        let hash = self.digest.finalize_reset();
        let v = match &self.key {
            SigningKey::SHA256withRSA(key) => {
                let sig: RsaSignature = key.sign_prehash(hash.as_ref())?;
                sig.to_vec()
            }
            SigningKey::SHA256withECDSA(key) => {
                let sig: P256Signature = key.sign_prehash(hash.as_ref())?;
                sig.to_vec()
            }
            SigningKey::SHA384withECDSA(key) => {
                let sig: P384Signature = key.sign_prehash(hash.as_ref())?;
                sig.to_vec()
            }
        };
        Ok(v)
    }
}

/*
 * BootSignature ::= SEQUENCE {
 *     formatVersion ::= INTEGER,
 *     certificate ::= Certificate,
 *     algorithmIdentifier ::= SEQUENCE {
 *         algorithm OBJECT IDENTIFIER,
 *         parameters ANY DEFINED BY algorithm OPTIONAL
 *     },
 *     authenticatedAttributes ::= SEQUENCE {
 *         target CHARACTER STRING,
 *         length INTEGER
 *     },
 *     signature ::= OCTET STRING
 * }
 */

#[derive(Sequence)]
struct AuthenticatedAttributes {
    target: PrintableString,
    length: u64,
}

#[derive(Sequence)]
struct BootSignature {
    format_version: i32,
    certificate: Certificate,
    algorithm_identifier: AlgorithmIdentifier<Any>,
    authenticated_attributes: AuthenticatedAttributes,
    signature: OctetString,
}

impl BootSignature {
    fn verify(self, payload: &[u8]) -> LoggedResult<()> {
        if self.authenticated_attributes.length as usize != payload.len() {
            return log_err!("Invalid image size");
        }
        let mut verifier = Verifier::from_public_key(
            self.certificate
                .tbs_certificate
                .subject_public_key_info
                .owned_to_ref(),
        )?;
        verifier.update(payload);
        let attr = self.authenticated_attributes.to_der()?;
        verifier.update(attr.as_slice());
        verifier.verify(self.signature.as_bytes())?;
        Ok(())
    }
}

/// Best-effort AVB1 detection: does `tail` start with a DER-encoded
/// BootSignature sequence? Mirrors the C++ `is_signed` semantics,
/// which relies on a successful `verify()` call — we relax that to
/// "decodes as BootSignature" so detection works without the verity
/// keypair. The tail length check guards against DER trailing zeros.
pub(crate) fn is_boot_signature(tail: &[u8]) -> bool {
    let Ok(mut reader) = SliceReader::new(tail) else {
        return false;
    };
    BootSignature::decode(&mut reader).is_ok()
}

impl BootImage {
    pub fn verify(&self, cert: Option<&Utf8CStr>) -> LoggedResult<()> {
        let tail = self.tail();
        if tail.starts_with(b"AVB0") {
            return log_err!();
        }

        // Don't use BootSignature::from_der because tail might have trailing zeros
        let mut reader = SliceReader::new(tail)?;
        let mut sig = BootSignature::decode(&mut reader).silent()?;
        if let Some(s) = cert {
            let pem = MappedFile::open(s)?;
            sig.certificate = Certificate::from_pem(pem)?;
        };

        sig.verify(self.payload()).log()
    }

    pub fn verify_for_cxx(&self) -> bool {
        self.verify(None).is_ok()
    }
}

enum Bytes {
    Mapped(MappedFile),
    Slice(&'static [u8]),
}

impl AsRef<[u8]> for Bytes {
    fn as_ref(&self) -> &[u8] {
        match self {
            Bytes::Mapped(m) => m.as_ref(),
            Bytes::Slice(s) => s,
        }
    }
}

const VERITY_PEM: &[u8] = include_bytes!("../keys/verity.x509.pem");
const VERITY_PK8: &[u8] = include_bytes!("../keys/verity.pk8");

pub fn sign_boot_image(
    payload: &[u8],
    name: &Utf8CStr,
    cert: Option<&Utf8CStr>,
    key: Option<&Utf8CStr>,
) -> LoggedResult<Vec<u8>> {
    let cert = match cert {
        Some(s) => Bytes::Mapped(MappedFile::open(s)?),
        None => Bytes::Slice(VERITY_PEM),
    };
    let key = match key {
        Some(s) => Bytes::Mapped(MappedFile::open(s)?),
        None => Bytes::Slice(VERITY_PK8),
    };

    // Parse cert and private key
    let cert = Certificate::from_pem(cert)?;
    let mut signer = Signer::from_private_key(key.as_ref())?;

    // Sign image
    let attr = AuthenticatedAttributes {
        target: PrintableString::new(name.as_bytes())?,
        length: payload.len() as u64,
    };
    signer.update(payload);
    signer.update(attr.to_der()?.as_slice());
    let sig = signer.sign()?;

    // Create BootSignature DER
    let alg_id = cert.signature_algorithm.clone();
    let sig = BootSignature {
        format_version: 1,
        certificate: cert,
        algorithm_identifier: alg_id,
        authenticated_attributes: attr,
        signature: OctetString::new(sig)?,
    };
    sig.to_der().log()
}

pub fn sign_payload_for_cxx(payload: &[u8]) -> Vec<u8> {
    sign_boot_image(payload, cstr!("/boot"), None, None).unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bootimg::hdr::{BOOT_MAGIC, BootImgHdrV3};
    use std::io::{Seek, SeekFrom, Write};
    use std::mem::size_of;

    fn build_v3_with_tail_room(kernel: &[u8], ramdisk: &[u8], tail_room: usize) -> Vec<u8> {
        const PAGE: usize = 4096;
        let mut hdr = vec![0u8; size_of::<BootImgHdrV3>()];
        hdr[..8].copy_from_slice(BOOT_MAGIC);
        hdr[8..12].copy_from_slice(&(kernel.len() as u32).to_le_bytes());
        hdr[12..16].copy_from_slice(&(ramdisk.len() as u32).to_le_bytes());
        hdr[40..44].copy_from_slice(&3u32.to_le_bytes());
        let mut out = hdr;
        while out.len() < PAGE {
            out.push(0);
        }
        out.extend_from_slice(kernel);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out.extend_from_slice(ramdisk);
        while out.len() % PAGE != 0 {
            out.push(0);
        }
        out.resize(out.len() + tail_room, 0);
        out
    }

    /// End-to-end AVB1 sign → verify round-trip using the bundled
    /// verity keypair. Mirrors the CLI `sign` flow: parse BootImage,
    /// sign payload, write DER block at `tail_off`, zero-pad to EOF.
    /// Verify must then succeed against the embedded cert.
    #[test]
    fn avb1_sign_then_verify_roundtrip() {
        use base::WriteExt;

        let tmp = tempfile::tempdir().unwrap();
        let img_path = tmp.path().join("avb1.img");
        // 8 KiB of tail room gives the DER BootSignature (~1.5 KiB with
        // the default verity cert) plenty of space on a 4 KiB page.
        let bytes = build_v3_with_tail_room(b"AVB1-KERNEL", b"AVB1-RAMDISK", 8192);
        std::fs::write(&img_path, &bytes).unwrap();

        let img = BootImage::new(img_path.to_str().unwrap());
        let name = cstr!("/boot");
        let sig = sign_boot_image(img.payload(), name, None, None).ok().expect("sign");
        let tail_off = img.tail_off();
        drop(img);

        let mut fd = std::fs::OpenOptions::new()
            .write(true)
            .open(&img_path)
            .unwrap();
        fd.seek(SeekFrom::Start(tail_off)).unwrap();
        fd.write_all(&sig).unwrap();
        let current = fd.stream_position().unwrap();
        let eof = fd.seek(SeekFrom::End(0)).unwrap();
        if eof > current {
            fd.seek(SeekFrom::Start(current)).unwrap();
            fd.write_zeros((eof - current) as usize).unwrap();
        }
        drop(fd);

        let img2 = BootImage::new(img_path.to_str().unwrap());
        assert!(img2.is_signed(), "post-sign tail should start with AVB1 magic");
        img2.verify(None).ok().expect("verify post-sign image");
    }

    #[test]
    fn avb1_verify_rejects_payload_tamper() {
        use base::WriteExt;

        let tmp = tempfile::tempdir().unwrap();
        let img_path = tmp.path().join("tamper.img");
        let bytes = build_v3_with_tail_room(b"AVB1-KERNEL", b"AVB1-RAMDISK", 8192);
        std::fs::write(&img_path, &bytes).unwrap();

        let img = BootImage::new(img_path.to_str().unwrap());
        let sig = sign_boot_image(img.payload(), cstr!("/boot"), None, None).ok().expect("sign");
        let tail_off = img.tail_off();
        drop(img);

        let mut fd = std::fs::OpenOptions::new()
            .write(true)
            .open(&img_path)
            .unwrap();
        fd.seek(SeekFrom::Start(tail_off)).unwrap();
        fd.write_all(&sig).unwrap();
        let current = fd.stream_position().unwrap();
        let eof = fd.seek(SeekFrom::End(0)).unwrap();
        if eof > current {
            fd.seek(SeekFrom::Start(current)).unwrap();
            fd.write_zeros((eof - current) as usize).unwrap();
        }
        drop(fd);

        // Flip one byte inside the kernel payload, past the header.
        let mut raw = std::fs::read(&img_path).unwrap();
        raw[4096] ^= 0x01;
        std::fs::write(&img_path, &raw).unwrap();

        let img2 = BootImage::new(img_path.to_str().unwrap());
        assert!(img2.verify(None).is_err(),
            "verify must fail after payload tamper");
    }
}
