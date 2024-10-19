use std::io;

use tokio_util::{
    bytes::{Buf, BufMut, BytesMut},
    codec::{Decoder, Encoder},
};
use winnow::{
    stream::{Offset, Stream},
    Located,
};

use crate::{parser, Header, Message, Name, Question, ResourceRecord};

pub struct DnsCodec;

impl Decoder for DnsCodec {
    type Item = Message;

    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let input = &mut Located::new(src.as_ref());
        let start = input.checkpoint();
        match parser::message(input) {
            Ok(message) => {
                src.advance(input.offset_from(&start));
                Ok(Some(message))
            }
            Err(winnow::error::ErrMode::Incomplete(_)) => Ok(None),
            Err(_) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Failed to decode DNS Message",
            )),
        }
    }
}

impl Encoder<Message> for DnsCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Message, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encode(item.header, dst)?;
        for question in item.question {
            self.encode(question, dst)?;
        }
        for rr in item.answer {
            self.encode(rr, dst)?;
        }
        for rr in item.authority {
            self.encode(rr, dst)?;
        }
        for rr in item.additional {
            self.encode(rr, dst)?;
        }
        Ok(())
    }
}

impl Encoder<Header> for DnsCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Header, dst: &mut BytesMut) -> Result<(), Self::Error> {
        dst.reserve(12);
        dst.put_u16(item.id);
        dst.put_u16(item.flags.raw_value());
        dst.put_u16(item.qd_count);
        dst.put_u16(item.an_count);
        dst.put_u16(item.ns_count);
        dst.put_u16(item.ar_count);
        Ok(())
    }
}

impl Encoder<Question> for DnsCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Question, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encode(item.qname, dst)?;
        dst.put_u16(item.qtype);
        dst.put_u16(item.qclass);
        Ok(())
    }
}

impl Encoder<ResourceRecord> for DnsCodec {
    type Error = io::Error;

    fn encode(&mut self, item: ResourceRecord, dst: &mut BytesMut) -> Result<(), Self::Error> {
        self.encode(item.name, dst)?;
        dst.put_u16(item.r#type);
        dst.put_u16(item.class);
        dst.put_u32(item.ttl);
        dst.put_u16(item.rdlength);
        dst.put(item.rdata.as_slice());
        Ok(())
    }
}

impl Encoder<Name> for DnsCodec {
    type Error = io::Error;

    fn encode(&mut self, item: Name, dst: &mut BytesMut) -> Result<(), Self::Error> {
        // Don't worry about compression when encoding
        item.labels.iter().for_each(|label| {
            dst.put_u8(label.len().try_into().unwrap());
            dst.put(label.as_bytes());
        });
        dst.put_u8(0);
        Ok(())
    }
}
