#![allow(dead_code, non_camel_case_types, non_upper_case_globals, unused_variables)]
#[macro_use]
extern crate error_chain;
extern crate hex;
#[macro_use]
extern crate log;
extern crate mach_o_sys;
extern crate macho;
extern crate memmap;
#[macro_use]
extern crate nom;
extern crate ring;

mod errors;

use hex::ToHex;
use macho::{LcType, MachObject};
use memmap::{Mmap, Protection};
use nom::{be_u8, be_u32, le_u32, IResult};
use ring::digest::{self, Digest, SHA1};
use std::boxed::Box;
use std::fmt;
use std::io::Write;
use std::fs::File;
use std::path::Path;
use std::str;

pub use errors::*;

pub enum SignatureValidity {
    Valid,
    Invalid,
}

fn do_hash(bytes: &[u8], hash_type: SecCSDigestAlgorithm) -> Digest {
    match hash_type {
        SecCSDigestAlgorithm::kSecCodeSignatureHashSHA1 => {
            digest::digest(&SHA1, bytes)
        }
        _ => unimplemented!(),
    }
}

fn code_hashes(data: &[u8], hash_type: SecCSDigestAlgorithm, page_size: u32, code_limit: u32) -> Vec<Digest> {
    let bytes = &data[..code_limit as usize];
    bytes.chunks(page_size as usize)
        .map(|c| {
            do_hash(c, hash_type)
        })
        .collect()
}

pub fn verify_signature<P>(path: P) -> Result<SignatureValidity>
     where P: AsRef<Path>,
{
    with_signature(path, |sig, data| {
        if let Some(cd) = sig.code_directory() {
            //TODO: calculate hashes for special slots
            let calc_hashes = code_hashes(data, cd.hash_type, cd.page_size, cd.code_limit);
            let (_special_hashes, code_hashes) = cd.hashes.split_at(cd.special_slots as usize);
            let eq = code_hashes.iter().zip(calc_hashes).all(|(h, o)| *h == o);
            if eq {
                Ok(SignatureValidity::Valid)
            } else {
                Ok(SignatureValidity::Invalid)
            }
        } else {
            bail!("Missing CodeDirectory")
        }
    })
}

fn get_signature<'a, 'b>(macho: &MachObject<'a>, data: &'b [u8]) -> Result<EmbeddedSignature<'b>>
{
    // Locate the LC_CODE_SIGNATURE
    let codesig = match macho.commands.iter().filter(|c| c.cmd == LcType::LC_CODE_SIGNATURE as u32).next() {
        None => bail!("Missing LC_CODE_SIGNATURE load command"),
        Some(c) => c,
    };
    let datacmd = parse_linkedit_command(codesig.data)?;
    // Get the actual bytes of the signature blob from the linkedit segment
    let codesig_data = &data[datacmd.dataoff as usize..(datacmd.dataoff + datacmd.datasize) as usize];
    let codesig_blob = parse_blob(codesig_data)?;
    if let Blob::EmbeddedSignature(sig) = codesig_blob {
        Ok(sig)
    } else {
        bail!(ErrorKind::IncorrectBlobType)
    }
}

fn with_signature<P, F, T>(path: P, callback: F) -> Result<T>
    where P: AsRef<Path>,
          for<'a> F: FnOnce(EmbeddedSignature<'a>, &'a [u8]) -> Result<T>,
{
    let data = Mmap::open_path(path, Protection::Read)?;
    let buf = unsafe { data.as_slice() };
    let m = MachObject::parse(buf)?;
    let sig = get_signature(&m, buf)?;
    callback(sig, buf)
}

/// Print information about the embedded code signature of `path` to stdout.
pub fn dump_signature<P>(path: P) -> Result<()>
    where P: AsRef<Path>,

{
    with_signature(path, |sig, _| {
        println!("{:?}", sig);
        Ok(())
    })
}

/// Extract the embedded code signature of `input_path` and write it to `output_path`.
pub fn extract_signature<P, Q>(input_path: P, output_path: Q) -> Result<()>
    where P: AsRef<Path>,
          Q: AsRef<Path>,
{
    with_signature(input_path, |sig, _| {
        let pkcs7 = match sig.pkcs7_signature() {
            None => bail!("PKCS#7 signature not found"),
            Some(s) => s,
        };
        let mut f = File::create(output_path)?;
        f.write_all(pkcs7)?;
        Ok(())
    })
}

struct Hash<'a> {
    bytes: &'a [u8],
}

impl<'a> fmt::Debug for Hash<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Hash {{ ")?;
        self.bytes.write_hex(f)?;
        write!(f, " }}")
    }
}

impl<'a, T> PartialEq<T> for Hash<'a>
    where T: AsRef<[u8]>,
{
    fn eq(&self, other: &T) -> bool {
        self.bytes == other.as_ref()
    }
}

macro_rules! enum_tryfrom {
    ($name:ident : $t:ty { $( $e:ident = $v:expr, )* }) => {
        #[repr(u8)]
        #[derive(Clone, Copy, Debug)]
        enum $name {
            $( $e = $v, )*
        }

        impl $name {
            pub fn try_from(val: $t) -> Option<$name> {
                $(
                    if val == $v as $t {
                        return Some($name::$e);
                    }
                )*
                return None
            }
        }
    }
}

enum_tryfrom!(SecCSDigestAlgorithm: u8 {
    kSecCodeSignatureNoHash = 0,
    kSecCodeSignatureHashSHA1 = 1,
    kSecCodeSignatureHashSHA256 = 2,
    kSecCodeSignatureHashSHA256Truncated = 3,
    kSecCodeSignatureHashSHA384	= 4,
});

#[repr(u32)]
#[derive(Clone, Copy)]
enum SuperBlobSlot {
    CodeDirectory = 0,
    Signature = 0x10000,
}

#[derive(Debug)]
struct CodeDirectory<'a> {
    cdhash: Digest,
    version: u32,
    flags: u32,
    hash_offset: u32,
    ident_offset: u32,
    special_slots: u32,
    code_slots: u32,
    code_limit: u32,
    hash_size: u8,
    hash_type: SecCSDigestAlgorithm,
    page_size: u32,
    scatter_offset: Option<u32>,
    ident: &'a str,
    hashes: Vec<Hash<'a>>,
}

struct WrappedData<'a> {
    data: &'a [u8],
}

impl<'a> fmt::Debug for WrappedData<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "...")
    }
}

struct EmbeddedSignature<'a> {
    super_: SuperBlob<'a>,
}

impl<'a> EmbeddedSignature<'a> {
    /// Get the PKCS#7 signature, if present.
    pub fn pkcs7_signature(&'a self) -> Option<&'a [u8]> {
        match self.super_.get_blob(SuperBlobSlot::Signature) {
            Some(&Blob::BlobWrapper(WrappedData { data })) => Some(data),
            _ => None,
        }
    }

    /// Get the embedded `CodeDirectory`, if present.
    pub fn code_directory(&'a self) -> Option<&'a CodeDirectory<'a>> {
        match self.super_.get_blob(SuperBlobSlot::CodeDirectory) {
            Some(&Blob::CodeDirectory(ref cd)) => Some(cd),
            _ => None,
        }
    }
}

impl<'a> fmt::Debug for EmbeddedSignature<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "EmbeddedSignature {{")?;
        for &(type_, ref blob) in self.super_.blobs.iter() {
            writeln!(f, "\t{}: {:?}", type_, blob)?;
        }
        writeln!(f, "}}")
    }
}

#[derive(Debug)]
enum Blob<'a> {
    Requirement { kind: u32, expr: Expr<'a> },
    Entitlements { super_: SuperBlob<'a> },
    CodeDirectory(CodeDirectory<'a>),
    Entitlement { plist: &'a str },
    BlobWrapper(WrappedData<'a>),
    EmbeddedSignature(EmbeddedSignature<'a>),
    DetachedSignature,
}

#[derive(Debug)]
struct SuperBlob<'a> {
    blobs: Vec<(u32, Blob<'a>)>,
}

impl<'a> SuperBlob<'a> {
    pub fn get_blob(&self, slot: SuperBlobSlot) -> Option<&'a Blob> {
        for &(type_, ref blob) in self.blobs.iter() {
            if type_ == slot as u32 {
                return Some(blob);
            }
        }
        None
    }
}

struct LinkeditCommand {
    pub dataoff: u32,
    pub datasize: u32,
}

named!(linkedit_command<&[u8], LinkeditCommand>,
       do_parse!(
           dataoff: le_u32 >>
               datasize: le_u32 >>
               (LinkeditCommand {
                   dataoff: dataoff,
                   datasize: datasize,
               })
               )
       );

named!(blob_index<&[u8], (u32, u32)>,
       do_parse!(
           type_: be_u32 >>
           offset: be_u32 >>
           ((type_, offset))
           )
       );

fn parse_super_blob_blobs<'a>(input: &'a [u8], indices: Vec<(u32, u32)>) -> SuperBlob<'a> {
    let mut blobs = vec![];
    for (type_, offset) in indices {
        let res = blob(&input[offset as usize..]);
        if let IResult::Done(_, blob) = res {
            blobs.push((type_, blob))
        } else {
            // DON'T PANIC
            panic!("Failed parsing superblob blobs!");
        }
    }
    SuperBlob {
        blobs: blobs,
    }
}

fn super_blob_<'a>(input: &'a [u8], container: &'a [u8]) -> IResult<&'a [u8], SuperBlob<'a>> {
    do_parse!(input,
              count: be_u32 >>
              indices: count!(blob_index, count as usize) >>
              (parse_super_blob_blobs(container, indices))
              )
}

macro_rules! super_blob {
    ($i:ident, $c:ident) => { super_blob_($i, $c) }
}

named!(data,
       do_parse!(
           length: be_u32 >>
               data: take!(length) >>
               //TODO: padding
               (data)
               ));

#[derive(Debug)]
enum Expr<'a> {
    False,
    True,
    Ident(&'a str),
    AppleAnchor,
    AnchorHash,
    InfoKeyValue,
    And(Box<Expr<'a>>, Box<Expr<'a>>),
    Or(Box<Expr<'a>>, Box<Expr<'a>>),
    CDHash,
    Not,
    InfoKeyField,
    CertField,
    TrustedCert,
    TrustedCerts,
    CertGeneric,
    AppleGenericAnchor,
    EntitlementField,
}

named!(expr_op_false<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 0 ][..]) >>
               (Expr::False)
               )
       );
named!(expr_op_true<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 1 ][..]) >>
               (Expr::True)
               )
       );

named!(expr_op_ident<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 2 ][..]) >>
               data: map_res!(data, str::from_utf8) >>
               (Expr::Ident(data))
               )
       );

named!(expr_op_apple_anchor<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 3 ][..]) >>
               (Expr::AppleAnchor)
               )
       );

named!(expr_op_anchor_hash<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 4 ][..]) >>
               (Expr::AnchorHash)
               )
       );

named!(expr_op_info_key_value<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 5 ][..]) >>
               (Expr::InfoKeyValue)
               )
       );

named!(expr_op_and<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 6 ][..]) >>
               a: expr >>
               b: expr >>
               (Expr::And(Box::new(a), Box::new(b)))
               )
       );

named!(expr_op_or<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 7 ][..]) >>
               a: expr >>
               b: expr >>
               (Expr::Or(Box::new(a), Box::new(b)))
               )
       );

named!(expr_op_cd_hash<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 8 ][..]) >>
               (Expr::CDHash)
               )
       );

named!(expr_op_not<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 9 ][..]) >>
               (Expr::Not)
               )
       );

named!(expr_op_info_key_field<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 10 ][..]) >>
               (Expr::InfoKeyField)
               )
       );

named!(expr_op_cert_field<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 11 ][..]) >>
               (Expr::CertField)
               )
       );

named!(expr_op_trusted_cert<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 12 ][..]) >>
               (Expr::TrustedCert)
               )
       );

named!(expr_op_trusted_certs<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 13 ][..]) >>
               (Expr::TrustedCerts)
               )
       );

named!(expr_op_cert_generic<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 14 ][..]) >>
               (Expr::CertGeneric)
               )
       );

named!(expr_op_apple_generic_anchor<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 15 ][..]) >>
               (Expr::AppleGenericAnchor)
               )
       );

named!(expr_op_entitlement_field<&[u8], Expr>,
       do_parse!(
           tag!(&[ 0, 0, 0, 16 ][..]) >>
               (Expr::EntitlementField)
               )
       );

named!(expr<&[u8], Expr>,
       alt_complete!(expr_op_false | expr_op_true | expr_op_ident |
                     expr_op_apple_anchor | expr_op_anchor_hash |
                     expr_op_info_key_value | expr_op_and | expr_op_or |
                     expr_op_cd_hash | expr_op_not | expr_op_info_key_field |
                     expr_op_cert_field | expr_op_trusted_cert |
                     expr_op_trusted_certs | expr_op_cert_generic |
                     expr_op_apple_generic_anchor | expr_op_entitlement_field));

named!(requirement<&[u8], Blob>,
       do_parse!(
           tag!(&[ 0xfa, 0xde, 0x0c, 0x00 ][..]) >>
               length: be_u32 >>
               kind: be_u32 >>
               expr: expr >>
               (Blob::Requirement {
                   kind: kind,
                   expr: expr,
               })
           )
       );

fn entitlements(input: &[u8]) -> IResult<&[u8], Blob> {
    do_parse!(input,
              tag!(&[ 0xfa, 0xde, 0x0c, 0x01 ][..]) >>
              length: be_u32 >>
              super_: super_blob!(input) >>
              (Blob::Entitlements { super_: super_ })
              )
}

fn cstr(data: &[u8], offset: usize)  -> Result<&str> {
    match &data[offset..].split(|&b| b == 0).map(str::from_utf8).next() {
        &Some(s) => s.chain_err(|| "Not a UTF-8 string"),
        &None => bail!("Unterminated C string"),
    }
}

fn get_hashes(input: &[u8], hash_offset: u32, special_slots: u32, code_slots: u32, hash_size: u8) -> Vec<Hash> {
    let real_offset = (hash_offset - hash_size as u32 * special_slots) as usize;
    input[real_offset..real_offset + ((special_slots + code_slots) * hash_size as u32) as usize]
        .chunks(hash_size as usize)
        .map(|bytes| Hash { bytes: bytes })
        .collect()
}

fn code_directory(input:&[u8]) -> IResult<&[u8], Blob> {
    do_parse!(input,
              tag!(&[ 0xfa, 0xde, 0x0c, 0x02 ][..]) >>
              length: be_u32 >>
              version: be_u32 >>
              flags: be_u32 >>
              hash_offset: be_u32 >>
              ident_offset: be_u32 >>
              special_slots: be_u32 >>
              code_slots: be_u32 >>
              code_limit: be_u32 >>
              hash_size: be_u8 >>
              hash_type: be_u8 >>
              // spare1
              be_u8 >>
              page_size: be_u8 >>
              // spare2
              be_u32 >>
              scatter_offset: cond!(version > 0x20100, be_u32) >>
              (Blob::CodeDirectory(CodeDirectory {
                  cdhash: digest::digest(&SHA1, &input[..length as usize]),
                  version: version,
                  flags: flags,
                  hash_offset: hash_offset,
                  ident_offset: ident_offset,
                  special_slots: special_slots,
                  code_slots: code_slots,
                  code_limit: code_limit,
                  hash_size: hash_size,
                  hash_type: SecCSDigestAlgorithm::try_from(hash_type).unwrap(),
                  page_size: 2u32.pow(page_size as u32),
                  scatter_offset: scatter_offset,
                  ident: cstr(input, ident_offset as usize).unwrap(),
                  hashes: get_hashes(input, hash_offset, special_slots, code_slots, hash_size),
              }))
              )
}

named!(entitlement<&[u8], Blob>,
       do_parse!(
           tag!(&[ 0xfa, 0xde, 0x71, 0x71 ][..]) >>
               length: be_u32 >>
               plist: map_res!(take!(length - 8), str::from_utf8) >>
               (Blob::Entitlement { plist: plist })
           )
       );

named!(blob_wrapper<&[u8], Blob>,
       do_parse!(
           tag!(&[ 0xfa, 0xde, 0x0b, 0x01 ][..]) >>
               length: be_u32 >>
               data: take!(length - 8) >>
               (Blob::BlobWrapper(WrappedData { data: data }))
           )
       );

fn embedded_signature(input: &[u8]) -> IResult<&[u8], Blob> {
    do_parse!(input,
              tag!(&[ 0xfa, 0xde, 0x0c, 0xc0 ][..]) >>
              length: be_u32 >>
              super_: super_blob!(input) >>
              (Blob::EmbeddedSignature(EmbeddedSignature { super_: super_ }))
              )
}

fn detached_signature(input: &[u8]) -> IResult<&[u8], Blob> {
    do_parse!(input,
              tag!(&[ 0xfa, 0xde, 0x0c, 0xc1 ][..]) >>
              length: be_u32 >>
              super_: super_blob!(input) >>
              (Blob::DetachedSignature)
              )
}

named!(blob<&[u8], Blob>,
       alt_complete!(requirement | entitlements | code_directory | entitlement | blob_wrapper | embedded_signature | detached_signature));

fn parse_blob(data: &[u8]) -> Result<Blob> {
    trace!("parse_blob {:?}, {} bytes", data.as_ptr(), data.len());
    match blob(data) {
        IResult::Done(_rest, blob) => Ok(blob),
        IResult::Incomplete(_) => bail!(ErrorKind::Incomplete),
        IResult::Error(e) => bail!(e),
    }
}

fn parse_linkedit_command(data: &[u8]) -> Result<LinkeditCommand> {
    trace!("parse_linkedit_command {:?}, {} bytes", data.as_ptr(), data.len());
    match linkedit_command(data) {
        IResult::Done(_rest, cmd) => Ok(cmd),
        IResult::Incomplete(_) => bail!(ErrorKind::Incomplete),
        IResult::Error(e) => bail!(e),
    }
}
