// Automatically generated rust module for 'update_metadata.proto' file

#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(unused_imports)]
#![allow(unknown_lints)]
#![allow(clippy::all)]
#![cfg_attr(rustfmt, rustfmt_skip)]


use quick_protobuf::{MessageInfo, MessageRead, MessageWrite, BytesReader, Writer, WriterBackend, Result};
use quick_protobuf::sizeofs::*;
use super::*;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Extent {
    pub start_block: Option<u64>,
    pub num_blocks: Option<u64>,
}

impl<'a> MessageRead<'a> for Extent {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.start_block = Some(r.read_uint64(bytes)?),
                Ok(16) => msg.num_blocks = Some(r.read_uint64(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Extent {
    fn get_size(&self) -> usize {
        0
        + self.start_block.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.num_blocks.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.start_block { w.write_with_tag(8, |w| w.write_uint64(*s))?; }
        if let Some(ref s) = self.num_blocks { w.write_with_tag(16, |w| w.write_uint64(*s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Signatures {
    pub signatures: Vec<mod_Signatures::Signature>,
}

impl<'a> MessageRead<'a> for Signatures {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.signatures.push(r.read_message::<mod_Signatures::Signature>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Signatures {
    fn get_size(&self) -> usize {
        0
        + self.signatures.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.signatures { w.write_with_tag(10, |w| w.write_message(s))?; }
        Ok(())
    }
}

pub mod mod_Signatures {

use super::*;

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct Signature {
    pub data: Option<Vec<u8>>,
    pub unpadded_signature_size: Option<u32>,
}

impl<'a> MessageRead<'a> for Signature {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(18) => msg.data = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(29) => msg.unpadded_signature_size = Some(r.read_fixed32(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for Signature {
    fn get_size(&self) -> usize {
        0
        + self.data.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.unpadded_signature_size.as_ref().map_or(0, |_| 1 + 4)
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.data { w.write_with_tag(18, |w| w.write_bytes(&**s))?; }
        if let Some(ref s) = self.unpadded_signature_size { w.write_with_tag(29, |w| w.write_fixed32(*s))?; }
        Ok(())
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct PartitionInfo {
    pub size: Option<u64>,
    pub hash: Option<Vec<u8>>,
}

impl<'a> MessageRead<'a> for PartitionInfo {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.size = Some(r.read_uint64(bytes)?),
                Ok(18) => msg.hash = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for PartitionInfo {
    fn get_size(&self) -> usize {
        0
        + self.size.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.hash.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.size { w.write_with_tag(8, |w| w.write_uint64(*s))?; }
        if let Some(ref s) = self.hash { w.write_with_tag(18, |w| w.write_bytes(&**s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct InstallOperation {
    pub type_pb: mod_InstallOperation::Type,
    pub data_offset: Option<u64>,
    pub data_length: Option<u64>,
    pub src_extents: Vec<Extent>,
    pub src_length: Option<u64>,
    pub dst_extents: Vec<Extent>,
    pub dst_length: Option<u64>,
    pub data_sha256_hash: Option<Vec<u8>>,
    pub src_sha256_hash: Option<Vec<u8>>,
}

impl<'a> MessageRead<'a> for InstallOperation {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.type_pb = r.read_enum(bytes)?,
                Ok(16) => msg.data_offset = Some(r.read_uint64(bytes)?),
                Ok(24) => msg.data_length = Some(r.read_uint64(bytes)?),
                Ok(34) => msg.src_extents.push(r.read_message::<Extent>(bytes)?),
                Ok(40) => msg.src_length = Some(r.read_uint64(bytes)?),
                Ok(50) => msg.dst_extents.push(r.read_message::<Extent>(bytes)?),
                Ok(56) => msg.dst_length = Some(r.read_uint64(bytes)?),
                Ok(66) => msg.data_sha256_hash = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(74) => msg.src_sha256_hash = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for InstallOperation {
    fn get_size(&self) -> usize {
        0
        + 1 + sizeof_varint(*(&self.type_pb) as u64)
        + self.data_offset.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.data_length.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.src_extents.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.src_length.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.dst_extents.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.dst_length.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.data_sha256_hash.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.src_sha256_hash.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_with_tag(8, |w| w.write_enum(*&self.type_pb as i32))?;
        if let Some(ref s) = self.data_offset { w.write_with_tag(16, |w| w.write_uint64(*s))?; }
        if let Some(ref s) = self.data_length { w.write_with_tag(24, |w| w.write_uint64(*s))?; }
        for s in &self.src_extents { w.write_with_tag(34, |w| w.write_message(s))?; }
        if let Some(ref s) = self.src_length { w.write_with_tag(40, |w| w.write_uint64(*s))?; }
        for s in &self.dst_extents { w.write_with_tag(50, |w| w.write_message(s))?; }
        if let Some(ref s) = self.dst_length { w.write_with_tag(56, |w| w.write_uint64(*s))?; }
        if let Some(ref s) = self.data_sha256_hash { w.write_with_tag(66, |w| w.write_bytes(&**s))?; }
        if let Some(ref s) = self.src_sha256_hash { w.write_with_tag(74, |w| w.write_bytes(&**s))?; }
        Ok(())
    }
}

pub mod mod_InstallOperation {


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    REPLACE = 0,
    REPLACE_BZ = 1,
    MOVE = 2,
    BSDIFF = 3,
    SOURCE_COPY = 4,
    SOURCE_BSDIFF = 5,
    REPLACE_XZ = 8,
    ZERO = 6,
    DISCARD = 7,
    BROTLI_BSDIFF = 10,
    PUFFDIFF = 9,
    ZUCCHINI = 11,
    LZ4DIFF_BSDIFF = 12,
    LZ4DIFF_PUFFDIFF = 13,
}

impl Default for Type {
    fn default() -> Self {
        Type::REPLACE
    }
}

impl From<i32> for Type {
    fn from(i: i32) -> Self {
        match i {
            0 => Type::REPLACE,
            1 => Type::REPLACE_BZ,
            2 => Type::MOVE,
            3 => Type::BSDIFF,
            4 => Type::SOURCE_COPY,
            5 => Type::SOURCE_BSDIFF,
            8 => Type::REPLACE_XZ,
            6 => Type::ZERO,
            7 => Type::DISCARD,
            10 => Type::BROTLI_BSDIFF,
            9 => Type::PUFFDIFF,
            11 => Type::ZUCCHINI,
            12 => Type::LZ4DIFF_BSDIFF,
            13 => Type::LZ4DIFF_PUFFDIFF,
            _ => Self::default(),
        }
    }
}

impl<'a> From<&'a str> for Type {
    fn from(s: &'a str) -> Self {
        match s {
            "REPLACE" => Type::REPLACE,
            "REPLACE_BZ" => Type::REPLACE_BZ,
            "MOVE" => Type::MOVE,
            "BSDIFF" => Type::BSDIFF,
            "SOURCE_COPY" => Type::SOURCE_COPY,
            "SOURCE_BSDIFF" => Type::SOURCE_BSDIFF,
            "REPLACE_XZ" => Type::REPLACE_XZ,
            "ZERO" => Type::ZERO,
            "DISCARD" => Type::DISCARD,
            "BROTLI_BSDIFF" => Type::BROTLI_BSDIFF,
            "PUFFDIFF" => Type::PUFFDIFF,
            "ZUCCHINI" => Type::ZUCCHINI,
            "LZ4DIFF_BSDIFF" => Type::LZ4DIFF_BSDIFF,
            "LZ4DIFF_PUFFDIFF" => Type::LZ4DIFF_PUFFDIFF,
            _ => Self::default(),
        }
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct CowMergeOperation {
    pub type_pb: Option<mod_CowMergeOperation::Type>,
    pub src_extent: Option<Extent>,
    pub dst_extent: Option<Extent>,
    pub src_offset: Option<u32>,
}

impl<'a> MessageRead<'a> for CowMergeOperation {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.type_pb = Some(r.read_enum(bytes)?),
                Ok(18) => msg.src_extent = Some(r.read_message::<Extent>(bytes)?),
                Ok(26) => msg.dst_extent = Some(r.read_message::<Extent>(bytes)?),
                Ok(32) => msg.src_offset = Some(r.read_uint32(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for CowMergeOperation {
    fn get_size(&self) -> usize {
        0
        + self.type_pb.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.src_extent.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.dst_extent.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.src_offset.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.type_pb { w.write_with_tag(8, |w| w.write_enum(*s as i32))?; }
        if let Some(ref s) = self.src_extent { w.write_with_tag(18, |w| w.write_message(s))?; }
        if let Some(ref s) = self.dst_extent { w.write_with_tag(26, |w| w.write_message(s))?; }
        if let Some(ref s) = self.src_offset { w.write_with_tag(32, |w| w.write_uint32(*s))?; }
        Ok(())
    }
}

pub mod mod_CowMergeOperation {


#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Type {
    COW_COPY = 0,
    COW_XOR = 1,
    COW_REPLACE = 2,
}

impl Default for Type {
    fn default() -> Self {
        Type::COW_COPY
    }
}

impl From<i32> for Type {
    fn from(i: i32) -> Self {
        match i {
            0 => Type::COW_COPY,
            1 => Type::COW_XOR,
            2 => Type::COW_REPLACE,
            _ => Self::default(),
        }
    }
}

impl<'a> From<&'a str> for Type {
    fn from(s: &'a str) -> Self {
        match s {
            "COW_COPY" => Type::COW_COPY,
            "COW_XOR" => Type::COW_XOR,
            "COW_REPLACE" => Type::COW_REPLACE,
            _ => Self::default(),
        }
    }
}

}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct PartitionUpdate {
    pub partition_name: String,
    pub run_postinstall: Option<bool>,
    pub postinstall_path: Option<String>,
    pub filesystem_type: Option<String>,
    pub new_partition_signature: Vec<mod_Signatures::Signature>,
    pub old_partition_info: Option<PartitionInfo>,
    pub new_partition_info: Option<PartitionInfo>,
    pub operations: Vec<InstallOperation>,
    pub postinstall_optional: Option<bool>,
    pub hash_tree_data_extent: Option<Extent>,
    pub hash_tree_extent: Option<Extent>,
    pub hash_tree_algorithm: Option<String>,
    pub hash_tree_salt: Option<Vec<u8>>,
    pub fec_data_extent: Option<Extent>,
    pub fec_extent: Option<Extent>,
    pub fec_roots: u32,
    pub version: Option<String>,
    pub merge_operations: Vec<CowMergeOperation>,
    pub estimate_cow_size: Option<u64>,
}

impl<'a> MessageRead<'a> for PartitionUpdate {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = PartitionUpdate {
            fec_roots: 2u32,
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.partition_name = r.read_string(bytes)?.to_owned(),
                Ok(16) => msg.run_postinstall = Some(r.read_bool(bytes)?),
                Ok(26) => msg.postinstall_path = Some(r.read_string(bytes)?.to_owned()),
                Ok(34) => msg.filesystem_type = Some(r.read_string(bytes)?.to_owned()),
                Ok(42) => msg.new_partition_signature.push(r.read_message::<mod_Signatures::Signature>(bytes)?),
                Ok(50) => msg.old_partition_info = Some(r.read_message::<PartitionInfo>(bytes)?),
                Ok(58) => msg.new_partition_info = Some(r.read_message::<PartitionInfo>(bytes)?),
                Ok(66) => msg.operations.push(r.read_message::<InstallOperation>(bytes)?),
                Ok(72) => msg.postinstall_optional = Some(r.read_bool(bytes)?),
                Ok(82) => msg.hash_tree_data_extent = Some(r.read_message::<Extent>(bytes)?),
                Ok(90) => msg.hash_tree_extent = Some(r.read_message::<Extent>(bytes)?),
                Ok(98) => msg.hash_tree_algorithm = Some(r.read_string(bytes)?.to_owned()),
                Ok(106) => msg.hash_tree_salt = Some(r.read_bytes(bytes)?.to_owned()),
                Ok(114) => msg.fec_data_extent = Some(r.read_message::<Extent>(bytes)?),
                Ok(122) => msg.fec_extent = Some(r.read_message::<Extent>(bytes)?),
                Ok(128) => msg.fec_roots = r.read_uint32(bytes)?,
                Ok(138) => msg.version = Some(r.read_string(bytes)?.to_owned()),
                Ok(146) => msg.merge_operations.push(r.read_message::<CowMergeOperation>(bytes)?),
                Ok(152) => msg.estimate_cow_size = Some(r.read_uint64(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for PartitionUpdate {
    fn get_size(&self) -> usize {
        0
        + 1 + sizeof_len((&self.partition_name).len())
        + self.run_postinstall.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.postinstall_path.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.filesystem_type.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.new_partition_signature.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.old_partition_info.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.new_partition_info.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.operations.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.postinstall_optional.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.hash_tree_data_extent.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.hash_tree_extent.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.hash_tree_algorithm.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.hash_tree_salt.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.fec_data_extent.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.fec_extent.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + if self.fec_roots == 2u32 { 0 } else { 2 + sizeof_varint(*(&self.fec_roots) as u64) }
        + self.version.as_ref().map_or(0, |m| 2 + sizeof_len((m).len()))
        + self.merge_operations.iter().map(|s| 2 + sizeof_len((s).get_size())).sum::<usize>()
        + self.estimate_cow_size.as_ref().map_or(0, |m| 2 + sizeof_varint(*(m) as u64))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_with_tag(10, |w| w.write_string(&**&self.partition_name))?;
        if let Some(ref s) = self.run_postinstall { w.write_with_tag(16, |w| w.write_bool(*s))?; }
        if let Some(ref s) = self.postinstall_path { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.filesystem_type { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        for s in &self.new_partition_signature { w.write_with_tag(42, |w| w.write_message(s))?; }
        if let Some(ref s) = self.old_partition_info { w.write_with_tag(50, |w| w.write_message(s))?; }
        if let Some(ref s) = self.new_partition_info { w.write_with_tag(58, |w| w.write_message(s))?; }
        for s in &self.operations { w.write_with_tag(66, |w| w.write_message(s))?; }
        if let Some(ref s) = self.postinstall_optional { w.write_with_tag(72, |w| w.write_bool(*s))?; }
        if let Some(ref s) = self.hash_tree_data_extent { w.write_with_tag(82, |w| w.write_message(s))?; }
        if let Some(ref s) = self.hash_tree_extent { w.write_with_tag(90, |w| w.write_message(s))?; }
        if let Some(ref s) = self.hash_tree_algorithm { w.write_with_tag(98, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.hash_tree_salt { w.write_with_tag(106, |w| w.write_bytes(&**s))?; }
        if let Some(ref s) = self.fec_data_extent { w.write_with_tag(114, |w| w.write_message(s))?; }
        if let Some(ref s) = self.fec_extent { w.write_with_tag(122, |w| w.write_message(s))?; }
        if self.fec_roots != 2u32 { w.write_with_tag(128, |w| w.write_uint32(*&self.fec_roots))?; }
        if let Some(ref s) = self.version { w.write_with_tag(138, |w| w.write_string(&**s))?; }
        for s in &self.merge_operations { w.write_with_tag(146, |w| w.write_message(s))?; }
        if let Some(ref s) = self.estimate_cow_size { w.write_with_tag(152, |w| w.write_uint64(*s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct DynamicPartitionGroup {
    pub name: String,
    pub size: Option<u64>,
    pub partition_names: Vec<String>,
}

impl<'a> MessageRead<'a> for DynamicPartitionGroup {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.name = r.read_string(bytes)?.to_owned(),
                Ok(16) => msg.size = Some(r.read_uint64(bytes)?),
                Ok(26) => msg.partition_names.push(r.read_string(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for DynamicPartitionGroup {
    fn get_size(&self) -> usize {
        0
        + 1 + sizeof_len((&self.name).len())
        + self.size.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.partition_names.iter().map(|s| 1 + sizeof_len((s).len())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        w.write_with_tag(10, |w| w.write_string(&**&self.name))?;
        if let Some(ref s) = self.size { w.write_with_tag(16, |w| w.write_uint64(*s))?; }
        for s in &self.partition_names { w.write_with_tag(26, |w| w.write_string(&**s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct VABCFeatureSet {
    pub threaded: Option<bool>,
    pub batch_writes: Option<bool>,
}

impl<'a> MessageRead<'a> for VABCFeatureSet {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(8) => msg.threaded = Some(r.read_bool(bytes)?),
                Ok(16) => msg.batch_writes = Some(r.read_bool(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for VABCFeatureSet {
    fn get_size(&self) -> usize {
        0
        + self.threaded.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.batch_writes.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.threaded { w.write_with_tag(8, |w| w.write_bool(*s))?; }
        if let Some(ref s) = self.batch_writes { w.write_with_tag(16, |w| w.write_bool(*s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct DynamicPartitionMetadata {
    pub groups: Vec<DynamicPartitionGroup>,
    pub snapshot_enabled: Option<bool>,
    pub vabc_enabled: Option<bool>,
    pub vabc_compression_param: Option<String>,
    pub cow_version: Option<u32>,
    pub vabc_feature_set: Option<VABCFeatureSet>,
}

impl<'a> MessageRead<'a> for DynamicPartitionMetadata {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.groups.push(r.read_message::<DynamicPartitionGroup>(bytes)?),
                Ok(16) => msg.snapshot_enabled = Some(r.read_bool(bytes)?),
                Ok(24) => msg.vabc_enabled = Some(r.read_bool(bytes)?),
                Ok(34) => msg.vabc_compression_param = Some(r.read_string(bytes)?.to_owned()),
                Ok(40) => msg.cow_version = Some(r.read_uint32(bytes)?),
                Ok(50) => msg.vabc_feature_set = Some(r.read_message::<VABCFeatureSet>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for DynamicPartitionMetadata {
    fn get_size(&self) -> usize {
        0
        + self.groups.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.snapshot_enabled.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.vabc_enabled.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.vabc_compression_param.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.cow_version.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.vabc_feature_set.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.groups { w.write_with_tag(10, |w| w.write_message(s))?; }
        if let Some(ref s) = self.snapshot_enabled { w.write_with_tag(16, |w| w.write_bool(*s))?; }
        if let Some(ref s) = self.vabc_enabled { w.write_with_tag(24, |w| w.write_bool(*s))?; }
        if let Some(ref s) = self.vabc_compression_param { w.write_with_tag(34, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.cow_version { w.write_with_tag(40, |w| w.write_uint32(*s))?; }
        if let Some(ref s) = self.vabc_feature_set { w.write_with_tag(50, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ApexInfo {
    pub package_name: Option<String>,
    pub version: Option<i64>,
    pub is_compressed: Option<bool>,
    pub decompressed_size: Option<i64>,
}

impl<'a> MessageRead<'a> for ApexInfo {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.package_name = Some(r.read_string(bytes)?.to_owned()),
                Ok(16) => msg.version = Some(r.read_int64(bytes)?),
                Ok(24) => msg.is_compressed = Some(r.read_bool(bytes)?),
                Ok(32) => msg.decompressed_size = Some(r.read_int64(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ApexInfo {
    fn get_size(&self) -> usize {
        0
        + self.package_name.as_ref().map_or(0, |m| 1 + sizeof_len((m).len()))
        + self.version.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.is_compressed.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.decompressed_size.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if let Some(ref s) = self.package_name { w.write_with_tag(10, |w| w.write_string(&**s))?; }
        if let Some(ref s) = self.version { w.write_with_tag(16, |w| w.write_int64(*s))?; }
        if let Some(ref s) = self.is_compressed { w.write_with_tag(24, |w| w.write_bool(*s))?; }
        if let Some(ref s) = self.decompressed_size { w.write_with_tag(32, |w| w.write_int64(*s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct ApexMetadata {
    pub apex_info: Vec<ApexInfo>,
}

impl<'a> MessageRead<'a> for ApexMetadata {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = Self::default();
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(10) => msg.apex_info.push(r.read_message::<ApexInfo>(bytes)?),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for ApexMetadata {
    fn get_size(&self) -> usize {
        0
        + self.apex_info.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        for s in &self.apex_info { w.write_with_tag(10, |w| w.write_message(s))?; }
        Ok(())
    }
}

#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Debug, Default, PartialEq, Clone)]
pub struct DeltaArchiveManifest {
    pub block_size: u32,
    pub signatures_offset: Option<u64>,
    pub signatures_size: Option<u64>,
    pub minor_version: u32,
    pub partitions: Vec<PartitionUpdate>,
    pub max_timestamp: Option<i64>,
    pub dynamic_partition_metadata: Option<DynamicPartitionMetadata>,
    pub partial_update: Option<bool>,
    pub apex_info: Vec<ApexInfo>,
    pub security_patch_level: Option<String>,
}

impl<'a> MessageRead<'a> for DeltaArchiveManifest {
    fn from_reader(r: &mut BytesReader, bytes: &'a [u8]) -> Result<Self> {
        let mut msg = DeltaArchiveManifest {
            block_size: 4096u32,
            ..Self::default()
        };
        while !r.is_eof() {
            match r.next_tag(bytes) {
                Ok(24) => msg.block_size = r.read_uint32(bytes)?,
                Ok(32) => msg.signatures_offset = Some(r.read_uint64(bytes)?),
                Ok(40) => msg.signatures_size = Some(r.read_uint64(bytes)?),
                Ok(96) => msg.minor_version = r.read_uint32(bytes)?,
                Ok(106) => msg.partitions.push(r.read_message::<PartitionUpdate>(bytes)?),
                Ok(112) => msg.max_timestamp = Some(r.read_int64(bytes)?),
                Ok(122) => msg.dynamic_partition_metadata = Some(r.read_message::<DynamicPartitionMetadata>(bytes)?),
                Ok(128) => msg.partial_update = Some(r.read_bool(bytes)?),
                Ok(138) => msg.apex_info.push(r.read_message::<ApexInfo>(bytes)?),
                Ok(146) => msg.security_patch_level = Some(r.read_string(bytes)?.to_owned()),
                Ok(t) => { r.read_unknown(bytes, t)?; }
                Err(e) => return Err(e),
            }
        }
        Ok(msg)
    }
}

impl MessageWrite for DeltaArchiveManifest {
    fn get_size(&self) -> usize {
        0
        + if self.block_size == 4096u32 { 0 } else { 1 + sizeof_varint(*(&self.block_size) as u64) }
        + self.signatures_offset.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.signatures_size.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + if self.minor_version == 0u32 { 0 } else { 1 + sizeof_varint(*(&self.minor_version) as u64) }
        + self.partitions.iter().map(|s| 1 + sizeof_len((s).get_size())).sum::<usize>()
        + self.max_timestamp.as_ref().map_or(0, |m| 1 + sizeof_varint(*(m) as u64))
        + self.dynamic_partition_metadata.as_ref().map_or(0, |m| 1 + sizeof_len((m).get_size()))
        + self.partial_update.as_ref().map_or(0, |m| 2 + sizeof_varint(*(m) as u64))
        + self.apex_info.iter().map(|s| 2 + sizeof_len((s).get_size())).sum::<usize>()
        + self.security_patch_level.as_ref().map_or(0, |m| 2 + sizeof_len((m).len()))
    }

    fn write_message<W: WriterBackend>(&self, w: &mut Writer<W>) -> Result<()> {
        if self.block_size != 4096u32 { w.write_with_tag(24, |w| w.write_uint32(*&self.block_size))?; }
        if let Some(ref s) = self.signatures_offset { w.write_with_tag(32, |w| w.write_uint64(*s))?; }
        if let Some(ref s) = self.signatures_size { w.write_with_tag(40, |w| w.write_uint64(*s))?; }
        if self.minor_version != 0u32 { w.write_with_tag(96, |w| w.write_uint32(*&self.minor_version))?; }
        for s in &self.partitions { w.write_with_tag(106, |w| w.write_message(s))?; }
        if let Some(ref s) = self.max_timestamp { w.write_with_tag(112, |w| w.write_int64(*s))?; }
        if let Some(ref s) = self.dynamic_partition_metadata { w.write_with_tag(122, |w| w.write_message(s))?; }
        if let Some(ref s) = self.partial_update { w.write_with_tag(128, |w| w.write_bool(*s))?; }
        for s in &self.apex_info { w.write_with_tag(138, |w| w.write_message(s))?; }
        if let Some(ref s) = self.security_patch_level { w.write_with_tag(146, |w| w.write_string(&**s))?; }
        Ok(())
    }
}

