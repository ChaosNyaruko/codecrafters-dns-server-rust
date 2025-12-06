#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Debug)]
struct DNSMessage {
    id: u16,
    qr: bool,   // false for question, true for reply
    opcode: u8, // 4bit
    aa: u8,
    tc: u8,
    rd: u8,
    ra: u8,
    reserved: u8, // 3bits: z + ad + cd
    rcode: u8,    // 4bits
    qdcount: u16,
    ancount: u16,
    nscount: u16,
    arcount: u16,
}

impl DNSMessage {
    fn pack(&self) -> [u8; 12] {
        let mut res = [0; 12];
        let mut i = 0;
        res[i..i + 2].copy_from_slice(&self.id.to_be_bytes());
        i += 2;

        if self.qr {
            res[i] |= 0b10000000;
        }
        res[i] |= ((self.opcode) & 0x0f) << 3;
        res[i] |= ((self.aa) & 0x01) << 2;
        res[i] |= ((self.tc) & 0x01) << 1;
        res[i] |= (self.rd) & 0x01;
        i += 1;

        res[i] |= ((self.ra) & 0x01) << 7;
        res[i] |= ((self.reserved) & 0x07) << 4;
        res[i] |= (self.rcode) & 0x0F;
        i += 1;

        res[i..i + 2].copy_from_slice(&self.qdcount.to_be_bytes());
        i += 2;
        res[i..i + 2].copy_from_slice(&self.ancount.to_be_bytes());
        i += 2;
        res[i..i + 2].copy_from_slice(&self.nscount.to_be_bytes());
        i += 2;
        res[i..i + 2].copy_from_slice(&self.arcount.to_be_bytes());
        i += 2;
        assert_eq!(i, 12);
        return res;
    }

    fn parse(buf: &[u8]) -> Self {
        let mut id = [0; 2];
        let mut i: usize = 0;
        id.copy_from_slice(&buf[i..i + 2]);
        i += 2;
        let id = u16::from_be_bytes(id);

        let mut meta = [0; 2];
        meta.copy_from_slice(&buf[i..i + 2]);
        i += 2;

        let qr = 0b10000000 & meta[0] == 1;
        let opcode = (meta[0] >> 3) & 0x0F;
        let aa = (meta[0] >> 2) & 0x1;
        let tc = (meta[0] >> 1) & 0x1;
        let rd = (meta[0]) & 0x1;

        let ra = (meta[1] >> 7) & 0x1;
        let reserved = (meta[1] >> 4) & 0x7;
        let rcode = (meta[1]) & 0xF;

        let mut qdcount = [0; 2];
        qdcount.copy_from_slice(&buf[i..i + 2]);
        i += 2;
        let qdcount = u16::from_be_bytes(qdcount);

        let mut ancount = [0; 2];
        ancount.copy_from_slice(&buf[i..i + 2]);
        i += 2;
        let ancount = u16::from_be_bytes(ancount);

        let mut nscount = [0; 2];
        nscount.copy_from_slice(&buf[i..i + 2]);
        i += 2;
        let nscount = u16::from_be_bytes(nscount);

        let mut arcount = [0; 2];
        arcount.copy_from_slice(&buf[i..i + 2]);
        i += 2;
        let arcount = u16::from_be_bytes(arcount);
        // assert_eq!(i, 12); // TODO: in the parse section, and we have more fields.

        Self {
            id,
            qr,
            opcode,
            aa,
            tc,
            rd,
            ra,
            reserved,
            rcode,
            qdcount,
            ancount,
            nscount,
            arcount,
        }
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let dm = DNSMessage::parse(&buf);
                println!("{:?}", dm);

                let r = DNSMessage {
                    id: 1234,
                    qr: true,
                    opcode: 0,
                    aa: 0,
                    tc: 0,
                    rd: 0,
                    ra: 0,
                    reserved: 0,
                    rcode: 0,
                    qdcount: 0,
                    ancount: 0,
                    nscount: 0,
                    arcount: 0,
                };
                let response = r.pack();
                udp_socket
                    .send_to(&response, source)
                    .expect("Failed to send response");
            }
            Err(e) => {
                eprintln!("Error receiving data: {}", e);
                break;
            }
        }
    }
}
