use std::io;

use dennis::{Client, Flags, Header, Message, Name, Question};

#[tokio::main(flavor = "current_thread")]
pub async fn main() -> io::Result<()> {
    let mut client = Client::connect("1.1.1.1:53".parse().unwrap()).await?;
    let message = Message {
        header: Header {
            id: 0x1234,
            flags: Flags::new_with_raw_value(0x0100),
            qd_count: 1,
            an_count: 0,
            ns_count: 0,
            ar_count: 0,
        },
        question: vec![Question {
            qname: Name::from("google.com"),
            qtype: 1,
            qclass: 0x0001,
        }],
        answer: Vec::new(),
        authority: Vec::new(),
        additional: Vec::new(),
    };
    let response = client.send_query(message).await?;
    println!("{:#?}", &response);
    Ok(())
}
