use bitbybit::{bitenum, bitfield};

/// DNS Message Format (RFC 1035 4.1)
///
/// All communications inside of the domain protocol are carried in a single format called a
/// message. The top level format of message is divided into 5 sections (some of which are empty in
/// certain cases).
///
/// The header section is always present. The header includes fields that specify which of the
/// remaining sections are present, and also specify whether the message is a query or a response, a
/// standard query or some other opcode, etc.
///
/// The names of the sections after the header are derived from their use in standard queries. The
/// question section contains fields that describe a question to a name server. These fields are a
/// query type (QTYPE), a query class (QCLASS), and a query domain name (QNAME). The last three
/// sections have the same format: a possibly empty list of concatenated resource records (RRs). The
/// answer section contains RRs that answer the question; the authority section contains RRs that
/// point toward an authoritative name server; the additional records section contains RRs which
/// relate to the query, but are not strictly answers for the question.
#[derive(Debug, PartialEq)]
pub struct Message {
    pub header: Header,
    pub question: Vec<Question>,
    pub answer: Vec<ResourceRecord>,
    pub authority: Vec<ResourceRecord>,
    pub additional: Vec<ResourceRecord>,
}

/// 4.1.1 Header section format
#[derive(Debug, PartialEq)]
pub struct Header {
    /// A 16 bit identifier assigned by the program that generates any kind of query.  This
    /// identifier is copied to the corresponding reply and can be used by the requester to match up
    /// replies to outstanding queries.
    pub id: u16,
    pub flags: Flags,
    /// an unsigned 16 bit integer specifying the number of entries in the question section.
    pub qd_count: u16,
    /// an unsigned 16 bit integer specifying the number of resource records in the answer section.
    pub an_count: u16,
    /// an unsigned 16 bit integer specifying the number of name server resource records in the
    /// authority records section.
    pub ns_count: u16,
    /// an unsigned 16 bit integer specifying the number of resource records in the additional
    /// records section.
    pub ar_count: u16,
}

#[bitfield(u16)]
#[derive(Debug, PartialEq)]
pub struct Flags {
    #[bit(0)]
    pub qr: bool,
    #[bits(1..=4)]
    pub opcode: Opcode,
    #[bit(5)]
    pub aa: bool,
    #[bit(6)]
    pub tc: bool,
    #[bit(7)]
    pub rd: bool,
    #[bit(8)]
    pub ra: bool,
    #[bits(9..=11)]
    pub z: u3,
    #[bits(12..=15)]
    pub rcode: Rcode,
}

#[bitenum(u4, exhaustive = false)]
pub enum Opcode {
    /// a standard query (QUERY)
    Query = 0,
    /// an inverse query (IQUERY)
    IQuery = 1,
    /// a server status request (STATUS)
    Status = 2,
    // 3-15 reserved for future use
}

#[bitenum(u4, exhaustive = false)]
pub enum Rcode {
    /// No error condition
    NoError = 0,
    /// Format error - The name server was unable to interpret the query.
    FormatError = 1,
    /// Server failure - The name server was unable to process this query due to a problem with the
    /// name server.
    ServerFailure = 2,
    /// Name Error - Meaningful only for responses from an authoritative name server, this code
    /// signifies that the domain name referenced in the query does not exist.
    NameError = 3,
    /// Not Implemented - The name server does not support the requested kind of query.
    NotImplemented = 4,
    /// Refused - The name server refuses to perform the specified operation for policy reasons. For
    /// example, a name server may not wish to provide the information to the particular requester,
    /// or a name server may not wish to perform a particular operation (e.g., zone transfer) for
    /// particular data.
    Refused = 5,
    // 6-15 reserved for future use
}

/// 4.1.2. Question section format
#[derive(Debug, PartialEq)]
pub struct Question {
    /// QNAME - a domain name represented as a sequence of labels, where each label consists of a
    /// length octet followed by that number of octets.  The domain name terminates with the zero
    /// length octet for the null label of the root. Note that this field may be an odd number of
    /// octets; no padding is used.
    pub qname: Name,
    /// QTYPE - a two octet code which specifies the type of the query. The values for this field
    /// include all codes valid for a TYPE field, together with some more general codes which can
    /// match more than one type of RR.
    pub qtype: u16,
    /// QCLASS - a two octet code that specifies the class of the query. For example, the QCLASS
    /// field is IN for the Internet.
    pub qclass: u16,
}

/// 4.1.3. Resource record format
///
/// The answer, authority, and additional sections all share the same format: a variable number of
/// resource records, where the number of records is specified in the corresponding count field in
/// the header.
#[derive(Debug, PartialEq)]
pub struct ResourceRecord {
    /// NAME - a domain name to which this resource record pertains.
    pub name: Name,
    /// TYPE - two octets containing one of the RR type codes. This field specifies the meaning of
    /// the data in the RDATA field.
    pub r#type: u16,
    /// CLASS - two octets which specify the class of the data in the RDATA field.
    pub class: u16,
    /// TTL - a 32 bit unsigned integer that specifies the time interval (in seconds) that the
    /// resource record may be cached before it should be discarded.  Zero values are interpreted to
    /// mean that the RR can only be used for the transaction in progress, and should not be cached.
    pub ttl: u32,
    /// RDLENGTH - an unsigned 16 bit integer that specifies the length in octets of the RDATA
    /// field.
    pub rdlength: u16,
    /// RDATA - a variable length string of octets that describes the resource.  The format of this
    /// information varies according to the TYPE and CLASS of the resource record. For example, the
    /// if the TYPE is A and the CLASS is IN, the RDATA field is a 4 octet ARPA Internet address.
    pub rdata: Vec<u8>,
}

#[derive(Debug, PartialEq)]
#[repr(transparent)]
pub struct Name {
    pub(crate) labels: Vec<String>,
}

impl From<&str> for Name {
    fn from(value: &str) -> Self {
        let labels = value.split(".").map(|s| s.to_owned()).collect();
        Self { labels }
    }
}
