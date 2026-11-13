use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{Context, Error, bail};
use x509_parser::{asn1_rs::FromDer, certificate::X509Certificate, extensions::GeneralName};

use crate::crypto::ecdsa;

const MAX_CERT_CHAIN_LOOP: usize = 10;

#[derive(Debug)]
pub(crate) struct CertificateEntry {
    pub data: Vec<u8>,
    pub extensions: Vec<u8>,
}

pub(crate) fn verify_certificate(
    hostname: &str,
    certificate_entries: Vec<CertificateEntry>,
    signature: Vec<u8>,
    transcript_hash: [u8; 32],
) -> Result<(), Error> {
    let mut certs: Vec<X509Certificate<'_>> = vec![];
    for c in certificate_entries.iter() {
        certs.push(x509_parser::parse_x509_certificate(&c.data)?.1);
    }

    if certs.is_empty() {
        bail!("no certificates received");
    }

    // verify leaf certificate signed the transcript
    let leaf_cert = &certs[0];
    let mut signed_content = [0x20u8; 130];
    signed_content[64..97].copy_from_slice(b"TLS 1.3, server CertificateVerify");
    signed_content[97] = 0x00;
    signed_content[98..].copy_from_slice(&transcript_hash);
    if !ecdsa::ecdsa_verify_p256(
        leaf_cert
            .public_key()
            .subject_public_key
            .data
            .as_ref()
            .try_into()?,
        &signed_content,
        &signature,
    ) {
        bail!("failed to verify certificate is valid");
    }

    verify_chain(&certs, leaf_cert).context("failed to verify certificate chain")?;

    // san validation
    let Some(san) = leaf_cert.subject_alternative_name()? else {
        bail!("missing subject alternative name on cert");
    };
    let mut matched = false;
    for name in &san.value.general_names {
        if let Ok(ip) = hostname.parse::<IpAddr>() {
            match name {
                GeneralName::IPAddress(bytes) => {
                    let cert_ip: Option<IpAddr> = match bytes.len() {
                        4 => Some(IpAddr::V4(Ipv4Addr::from(
                            <[u8; 4]>::try_from(*bytes).unwrap(),
                        ))),
                        16 => Some(IpAddr::V6(Ipv6Addr::from(
                            <[u8; 16]>::try_from(*bytes).unwrap(),
                        ))),
                        _ => None, // Malformed entry: RFC 5280 only allows 4 or 16 byte IPAddress SANs
                    };
                    if cert_ip == Some(ip) {
                        matched = true;
                    }
                }
                _ => {}
            }
        } else {
            match name {
                GeneralName::DNSName(dns) => {
                    if dns.eq_ignore_ascii_case(hostname) {
                        matched = true;
                    }
                }
                _ => {}
            }
        }
    }
    if !matched {
        bail!("faield to match subject alternative name with requested hostname");
    }

    Ok(())
}

fn verify_chain(
    certs: &Vec<X509Certificate<'_>>,
    leaf_cert: &X509Certificate<'_>,
) -> Result<(), Error> {
    // Verify the leaf certificate is from a trusted certificate authority.
    // Signature verification here is delegated to x509-parser's verify_signature
    // rather than hand-rolled since chains mix algorithms (RSA, P-256, P-384, ...)
    // our own ecdsa_verify_p256 can't cover.
    // The CertificateVerify check above stays hand-rolled
    // since that one is guaranteed P-256/SHA-256 by our own SignatureAlgorithms offer.
    let mut current = leaf_cert;
    for _ in 0..MAX_CERT_CHAIN_LOOP {
        if !current.validity().is_valid() {
            bail!("provided certificate is not valid");
        }
        let issuer_der = current.issuer().as_raw();
        let (_, issuer_any) = x509_parser::asn1_rs::Any::from_der(issuer_der)?;
        if let Some(anchor) = webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .find(|root| root.subject.as_ref() == issuer_any.data)
        {
            let (_, spki) = x509_parser::x509::SubjectPublicKeyInfo::from_der(
                anchor.subject_public_key_info.as_ref(),
            )?;
            current
                .verify_signature(Some(&spki))
                .context("failed to verify certificate chain")?;
            return Ok(());
        } else if let Some(intermediate) = certs[1..]
            .iter()
            .find(|c| c.subject().as_raw() == issuer_der)
        {
            if !intermediate
                .basic_constraints()?
                .map(|bc| bc.value.ca)
                .unwrap_or(false)
            {
                bail!("issuer is not a CA");
            }
            current
                .verify_signature(Some(intermediate.public_key()))
                .context("failed to verify certificate chain")?;
            current = intermediate;
        } else {
            bail!("unknown certificate authority");
        }
    }
    bail!("certificate chain too long")
}
