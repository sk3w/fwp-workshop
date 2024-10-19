//! A DNS library for hacking and education
//!
//! This crate was written as part of a hacking workshop "Fun With Protocols".
//! The purpose is to build a transparent MITM proxy tool for the DNS protocol.

mod message;
pub mod parser;
mod codec;

pub use codec::DnsCodec;
pub use message::{Flags, Header, Message, Name, Opcode, Question, Rcode, ResourceRecord};
