use winnow::{
    binary::{be_u16, be_u32, be_u8, length_take},
    combinator::{alt, preceded, repeat, repeat_till},
    token::take,
    Located, PResult, Parser,
};

use crate::{Flags, Header, Message, Name, Question, ResourceRecord};

pub fn message(input: &mut Located<&[u8]>) -> PResult<Message> {
    // 'Located' keeps a reference to the start of the stream for offset lookup of compressed names
    let header = header(input)?;
    let question = repeat(header.qd_count as usize, question).parse_next(input)?;
    let answer = repeat(header.an_count as usize, resource_record).parse_next(input)?;
    let authority = repeat(header.ns_count as usize, resource_record).parse_next(input)?;
    let additional = repeat(header.ar_count as usize, resource_record).parse_next(input)?;
    Ok(Message {
        header,
        question,
        answer,
        authority,
        additional,
    })
}

pub fn header(input: &mut Located<&[u8]>) -> PResult<Header> {
    let id = be_u16(input)?;
    let flags = be_u16(input)?;
    let qd_count = be_u16(input)?;
    let an_count = be_u16(input)?;
    let ns_count = be_u16(input)?;
    let ar_count = be_u16(input)?;
    Ok(Header {
        id,
        flags: Flags::new_with_raw_value(flags),
        qd_count,
        an_count,
        ns_count,
        ar_count,
    })
}

pub fn question(input: &mut Located<&[u8]>) -> PResult<Question> {
    let qname = name(input)?;
    let qtype = be_u16(input)?;
    let qclass = be_u16(input)?;
    Ok(Question {
        qname,
        qtype,
        qclass,
    })
}

pub fn resource_record(input: &mut Located<&[u8]>) -> PResult<ResourceRecord> {
    let name = name(input)?;
    let r#type = be_u16(input)?;
    let class = be_u16(input)?;
    let ttl = be_u32(input)?;
    let rdlength = be_u16(input)?;
    let rdata = take(rdlength).parse_next(input)?.to_owned();
    Ok(ResourceRecord {
        name,
        r#type,
        class,
        ttl,
        rdlength,
        rdata,
    })
}

pub fn name(input: &mut Located<&[u8]>) -> PResult<Name> {
    let (mut labels, end): (Vec<String>, _) =
        repeat_till(0.., label, name_end).parse_next(input)?;
    if let Some(pointer) = end {
        let input = &mut input.clone();
        input.reset_to_start();
        let recursive_name = preceded(take(pointer), name).parse_next(input)?;
        labels.extend(recursive_name.labels);
    }
    Ok(Name { labels })
}

fn label(input: &mut Located<&[u8]>) -> PResult<String> {
    let label = length_take(be_u8)
        .try_map(std::str::from_utf8)
        .map(|s| s.to_owned())
        .parse_next(input)?;
    Ok(label)
}

/// Parse the end of a possibly-compressed DNS name
///
/// A DNS name can end in either a null byte (no compression) or a pointer
fn name_end(input: &mut Located<&[u8]>) -> PResult<Option<u16>> {
    let pointer = alt((
        b"\0".value(None),
        be_u16.verify(|u| u > &0x3fff).map(|u| Some(u & 0x3fff)),
    ))
    .parse_next(input)?;
    Ok(pointer)
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use pretty_assertions::assert_eq;

    use super::*;

    #[test]
    fn parse_query() {
        // DNS request bytes from
        // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap
        let input = hex!(
            "10 32 01 00 00 01 00 00 00 00 00 00 06 67 6f 6f"
            "67 6c 65 03 63 6f 6d 00 00 10 00 01"
        )
        .as_ref();
        let output = message(&mut Located::new(input)).unwrap();
        let expected = Message {
            header: Header {
                id: 0x1032,
                flags: Flags::new_with_raw_value(0x0100),
                qd_count: 1,
                an_count: 0,
                ns_count: 0,
                ar_count: 0,
            },
            question: vec![Question {
                qname: Name::from("google.com"),
                qtype: 16,
                qclass: 0x0001,
            }],
            answer: Vec::new(),
            authority: Vec::new(),
            additional: Vec::new(),
        };
        assert_eq!(output, expected)
    }

    #[test]
    fn parse_response() {
        // DNS response bytes from
        // https://wiki.wireshark.org/uploads/__moin_import__/attachments/SampleCaptures/dns.cap
        let input = hex!(
            "10 32 81 80 00 01 00 01 00 00 00 00 06 67 6f 6f"
            "67 6c 65 03 63 6f 6d 00 00 10 00 01 c0 0c 00 10"
            "00 01 00 00 01 0e 00 10 0f 76 3d 73 70 66 31 20"
            "70 74 72 20 3f 61 6c 6c"
        )
        .as_ref();
        let output = message(&mut Located::new(input)).unwrap();
        let expected = Message {
            header: Header {
                id: 0x1032,
                flags: Flags::new_with_raw_value(0x8180),
                qd_count: 1,
                an_count: 1,
                ns_count: 0,
                ar_count: 0,
            },
            question: vec![Question {
                qname: Name::from("google.com"),
                qtype: 16,
                qclass: 0x0001,
            }],
            answer: vec![ResourceRecord {
                name: Name::from("google.com"),
                r#type: 16,
                class: 0x0001,
                ttl: 270,
                rdlength: 16,
                //rdata: hex!("0f763d7370663120707472203f616c6c").to_vec(),
                rdata: b"\x0fv=spf1 ptr ?all".to_vec(),
            }],
            authority: Vec::new(),
            additional: Vec::new(),
        };
        assert_eq!(output, expected)
    }
}
