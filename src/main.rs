#[allow(unused_imports)]
use std::net::UdpSocket;

#[derive(Debug, Clone, Copy)]
struct DNSHeader {
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

#[derive(Debug, Clone)]
struct DNSQuestion {
    name: String,
    r#type: u16,
    class: u16,
}

#[derive(Debug, Clone)]
struct DNSAnswer {
    question: DNSQuestion,
    ttl: i32,
    len: u16,
    data: Vec<u8>,
}

impl DNSAnswer {
    fn parse(buf: &[u8], i: &mut usize) -> Self {
        let q = DNSQuestionsParser { qdcount: 1 }.parse(buf, i);
        let ttl = u32::from_be_bytes(buf[*i..*i + 4].try_into().unwrap());
        *i = *i + 4;
        let len = u16::from_be_bytes(buf[*i..*i + 2].try_into().unwrap());
        *i = *i + 2;
        let data: Vec<u8> = buf[*i..*i + len as usize].to_vec();
        *i = *i + len as usize;
        DNSAnswer {
            question: q[0].clone(),
            ttl: ttl as i32,
            len,
            data,
        }
    }
    fn pack(&self) -> Vec<u8> {
        let mut res = self.question.pack();
        match self.question.r#type {
            1 => {
                res.extend_from_slice(&self.ttl.to_be_bytes());
                res.extend_from_slice(&self.len.to_be_bytes());
                res.extend_from_slice(&self.data);
            }
            err => {
                unimplemented!("type {err} not supported")
            }
        }
        return res;
    }
}

struct DNSQuestionsParser {
    qdcount: usize,
}

impl DNSQuestionsParser {
    fn parse(&mut self, buf: &[u8], i: &mut usize) -> Vec<DNSQuestion> {
        let mut questions = Vec::<DNSQuestion>::with_capacity(self.qdcount as usize);
        for _ in 0..self.qdcount {
            let question = DNSQuestion::parse_from_buf(buf, i);
            questions.push(question);
        }
        questions
    }
}

fn is_pointer(b: u8) -> bool {
    (b >> 6) & 0b11 == 0x3
}

impl DNSQuestion {
    fn name_from_label(buf: &[u8], i: &mut usize) -> String {
        let mut names = Vec::new();
        while buf[*i] != b'\0' && !is_pointer(buf[*i]) {
            let len = buf[*i] as usize;
            *i += 1;
            let label = String::from_utf8_lossy(&buf[*i..*i + len]).into_owned();
            names.push(label);
            *i += len;
        }
        if buf[*i] == b'\0' {
            *i += 1; // skip \0
        } else {
            // a sequence of labels + pointer
            assert_eq!(
                is_pointer(buf[*i]),
                true,
                "a label must be ending with 0 or a pointer"
            );
            let label = DNSQuestion::name_from_offset(buf, i);
            names.push(label);
        }

        return names.join(".");
    }

    fn name_from_offset(buf: &[u8], i: &mut usize) -> String {
        let mut offset =
            (u16::from_be_bytes(buf[*i..*i + 2].try_into().unwrap()) & 0x3FFF) as usize;
        *i += 2;

        return DNSQuestion::name_from_label(buf, &mut offset);
    }

    fn parse_from_buf(buf: &[u8], i: &mut usize) -> Self {
        let mut names = Vec::new();
        let label_or_pointer = (buf[*i] >> 6) & 0b11;
        match label_or_pointer {
            0 => {
                names.push(DNSQuestion::name_from_label(buf, i));
            }
            3 => {
                let label = DNSQuestion::name_from_offset(buf, i);
                names.push(label);
            }
            other => {
                unimplemented!("reserved compression type {other}")
            }
        }
        let name = names.join(".");

        let r#type = u16::from_be_bytes(buf[*i..*i + 2].try_into().unwrap());
        *i += 2;
        let class = u16::from_be_bytes(buf[*i..*i + 2].try_into().unwrap());
        *i += 2;

        Self {
            name,
            r#type,
            class,
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut res = Vec::new();
        let names = self.name.split('.');
        // self.name is guaranteed to be "ascii" text
        for x in names {
            let len = x.len() as u8;
            res.push(len);
            res.extend_from_slice(x.as_bytes());
        }
        res.push(0);
        res.extend_from_slice(&self.r#type.to_be_bytes());
        res.extend_from_slice(&self.class.to_be_bytes());
        res
    }
}

#[derive(Debug, Clone)]
struct DNSMessage {
    header: DNSHeader,
    questions: Vec<DNSQuestion>,
    answers: Vec<DNSAnswer>,
    authority: (),
    additional: (),
}

impl DNSHeader {
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

    fn parse_from_buf(buf: &[u8], i: &mut usize) -> Self {
        let mut id = [0; 2];
        id.copy_from_slice(&buf[*i..*i + 2]);
        *i += 2;
        let id = u16::from_be_bytes(id);

        let mut meta = [0; 2];
        meta.copy_from_slice(&buf[*i..*i + 2]);
        *i += 2;

        let qr = 0b10000000 & meta[0] == 1;
        let opcode = (meta[0] >> 3) & 0x0F;
        let aa = (meta[0] >> 2) & 0x1;
        let tc = (meta[0] >> 1) & 0x1;
        let rd = (meta[0]) & 0x1;

        let ra = (meta[1] >> 7) & 0x1;
        let reserved = (meta[1] >> 4) & 0x7;
        let rcode = (meta[1]) & 0xF;

        let mut qdcount = [0; 2];
        qdcount.copy_from_slice(&buf[*i..*i + 2]);
        *i += 2;
        let qdcount = u16::from_be_bytes(qdcount);

        let mut ancount = [0; 2];
        ancount.copy_from_slice(&buf[*i..*i + 2]);
        *i += 2;
        let ancount = u16::from_be_bytes(ancount);

        let mut nscount = [0; 2];
        nscount.copy_from_slice(&buf[*i..*i + 2]);
        *i += 2;
        let nscount = u16::from_be_bytes(nscount);

        let mut arcount = [0; 2];
        arcount.copy_from_slice(&buf[*i..*i + 2]);
        *i += 2;
        let arcount = u16::from_be_bytes(arcount);
        assert_eq!(*i, 12);

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

impl DNSMessage {
    fn forward_single_question(rm: &DNSMessage, i: usize) -> Self {
        DNSMessage {
            header: DNSHeader {
                id: rm.header.id,
                qr: false,
                opcode: rm.header.opcode,
                aa: 0,
                tc: 0,
                rd: 1, // NOTE: we want the resolver recursively resolve the query for our server
                ra: 0,
                reserved: 0,
                rcode: 0,
                qdcount: 1, // the tester resolver only support one question
                ancount: 0,
                nscount: 0,
                arcount: 0,
            },
            questions: vec![rm.questions[i].clone()],
            answers: Vec::new(),
            authority: (),
            additional: (),
        }
    }

    fn mock_resp(dm: &DNSMessage) -> Self {
        let qs = dm.questions.clone();
        DNSMessage {
            header: DNSHeader {
                id: dm.header.id,
                qr: true,
                opcode: dm.header.opcode,
                aa: 0,
                tc: 0,
                rd: dm.header.rd,
                ra: 0,
                reserved: 0,
                rcode: if dm.header.opcode == 0 { 0 } else { 4 }, // 4: not implemented,
                qdcount: dm.header.qdcount,
                ancount: dm.header.qdcount,
                nscount: 0,
                arcount: 0,
            },
            questions: qs.clone(),
            answers: qs
                .iter()
                .map(|q| DNSAnswer {
                    question: q.clone(),
                    ttl: 60,
                    len: 4,
                    data: vec![8, 8, 8, 8],
                })
                .collect(),
            authority: (),
            additional: (),
        }
    }

    fn from_forward(rm: &DNSMessage, dms: &Vec<DNSMessage>) -> Self {
        assert_eq!(dms.len(), rm.questions.len());
        let qs = rm.questions.clone();
        let mut answers = Vec::new();
        for dm in dms {
            for a in &dm.answers {
                answers.push(a.clone());
            }
        }

        DNSMessage {
            header: DNSHeader {
                id: rm.header.id,
                qr: true,
                opcode: rm.header.opcode,
                aa: 0,
                tc: 0,
                rd: rm.header.rd,
                ra: 1,
                reserved: 0,
                rcode: if rm.header.opcode == 0 { 0 } else { 4 }, // 4: not implemented,
                qdcount: rm.header.qdcount,
                ancount: dms.iter().map(|dm| dm.answers.len() as u16).sum::<u16>(),
                nscount: 0,
                arcount: 0,
            },
            questions: qs.clone(),
            answers: answers,
            authority: (),
            additional: (),
        }
    }

    fn parse(buf: &[u8]) -> Self {
        let mut i = 0;
        let header = DNSHeader::parse_from_buf(buf, &mut i);
        let mut p = DNSQuestionsParser {
            qdcount: header.qdcount as usize,
        };
        let questions = p.parse(buf, &mut i);
        let mut answers = Vec::new();
        for _ in 0..header.ancount {
            answers.push(DNSAnswer::parse(buf, &mut i));
        }
        eprintln!(
            "resolver parsed questions: {:?}, ancount: {}",
            questions, header.ancount,
        );
        eprintln!("resolver parsed answers: {:?}", answers);
        Self {
            header,
            questions,
            answers: answers,
            authority: (),
            additional: (),
        }
    }

    fn pack(&self) -> Vec<u8> {
        let mut res = Vec::new();
        let header = self.header.pack();
        res.extend_from_slice(&header);

        for i in 0..self.header.qdcount {
            let question = self.questions[i as usize].pack();
            res.extend(question);
        }

        for i in 0..self.header.ancount {
            let question = self.answers[i as usize].pack();
            res.extend(question);
        }

        return res;
    }
}

fn main() {
    // You can use print statements as follows for debugging, they'll be visible when running tests.
    println!("Logs from your program will appear here!");
    let args: Vec<_> = std::env::args().collect();
    let resolver = if args.len() >= 3 && args[1] == "--resolver" {
        args[2].clone()
    } else {
        "".to_string()
    };

    let udp_socket = UdpSocket::bind("127.0.0.1:2053").expect("Failed to bind to address");
    let mut buf = [0; 512];

    loop {
        match udp_socket.recv_from(&mut buf) {
            Ok((size, source)) => {
                println!("Received {} bytes from {}", size, source);
                let dm = DNSMessage::parse(&buf[..size]);
                eprintln!("we got request: {:?}", dm);

                let r = if resolver == "" {
                    DNSMessage::mock_resp(&dm)
                } else {
                    let mut dms = Vec::new();
                    for i in 0..dm.questions.len() {
                        let forward = DNSMessage::forward_single_question(&dm, i);
                        let forward = forward.pack();
                        let udp_socket =
                            UdpSocket::bind("0.0.0.0:0").expect("Failed to bind to address");
                        udp_socket
                            .send_to(&forward, &resolver)
                            .expect(&format!("send to resolver {}", resolver));
                        let mut resp = [0; 512];
                        let (size, source) = udp_socket
                            .recv_from(&mut resp)
                            .expect("receive from resolver");
                        assert_eq!(source.to_string(), resolver);
                        let r = DNSMessage::parse(&resp[..size]);
                        eprintln!("resolver gives me: {:?}", r);
                        dms.push(r);
                    }
                    DNSMessage::from_forward(&dm, &dms)
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
