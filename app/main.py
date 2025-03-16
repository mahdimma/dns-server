import socket
from enum import Flag, Enum


class HeaderFlags(Flag):
    QR = 0x8000
    OPCODE = 0x7800
    AA = 0x0400
    TC = 0x0200
    RD = 0x0100
    RA = 0x0080
    Z = 0x0070
    RCODE = 0x000F


class QuestionTypeEnum(Enum):
    A = 1
    NS = 2
    MD = 3
    MF = 4
    CNAME = 5
    SOA = 6
    MB = 7
    MG = 8
    MR = 9
    NULL = 10
    WKS = 11
    PTR = 12
    HINFO = 13
    MINFO = 14
    MX = 15
    TXT = 16


class QuestionClassEnum(Enum):
    IN = 1
    CS = 2
    CH = 3
    HS = 4


class Header:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.id = int.from_bytes(buf[0:2], byteorder="big")
        self.flags = int.from_bytes(buf[2:4], byteorder="big")
        self.qr = self.flags & 0x8000
        self.OPCODE = self.flags & 0x7800
        self.AA = self.flags & 0x0400
        self.TC = self.flags & 0x0200
        self.RD = self.flags & 0x0100
        self.RA = self.flags & 0x0080
        self.Z = self.flags & 0x0070
        self.RCODE = self.flags & 0x000F
        self.qdcount = int.from_bytes(buf[4:6], byteorder="big")
        self.ancount = int.from_bytes(buf[6:8], byteorder="big")
        self.nscount = int.from_bytes(buf[8:10], byteorder="big")
        self.arcount = int.from_bytes(buf[10:12], byteorder="big")

    def change_header(self, flag: HeaderFlags) -> None:
        self.flags = flag.value
        self.qr = self.flags & 0x8000
        self.OPCODE = self.flags & 0x7800
        self.AA = self.flags & 0x0400
        self.TC = self.flags & 0x0200
        self.RD = self.flags & 0x0100
        self.RA = self.flags & 0x0080
        self.Z = self.flags & 0x0070
        self.RCODE = self.flags & 0x000F

    def toByte(self) -> bytes:
        id_bytes = self.id.to_bytes(2, byteorder="big")
        flags_bytes = self.flags.to_bytes(2, byteorder="big")
        qdcount_bytes = self.qdcount.to_bytes(2, byteorder="big")
        ancount_bytes = self.ancount.to_bytes(2, byteorder="big")
        nscount_bytes = self.nscount.to_bytes(2, byteorder="big")
        arcount_bytes = self.arcount.to_bytes(2, byteorder="big")
        return (
            id_bytes
            + flags_bytes
            + qdcount_bytes
            + ancount_bytes
            + nscount_bytes
            + arcount_bytes
        )

    def __repr__(self):
        return (
            f"Header(id={self.id}, flags={self.flags}, qr={self.qr}, OPCODE={self.OPCODE}, "
            f"AA={self.AA}, TC={self.TC}, RD={self.RD}, RA={self.RA}, Z={self.Z}, RCODE={self.RCODE}, "
            f"qdcount={self.qdcount}, ancount={self.ancount}, nscount={self.nscount}, arcount={self.arcount})"
        )


class Questions:
    class Question:
        def __init__(self, buf: bytes):
            self.qname: list[str] = []
            self.bqname: list[bytes] = []
            self.bqnamecomplete: bytes = b""
            self.qtype: QuestionTypeEnum = None
            self.qclass: QuestionClassEnum = None
            self.buf = buf
            i = 0
            while True:
                length = buf[i]
                if length == 0:
                    i += 1
                    break
                self.bqname.append(buf[i + 1 : i + 1 + length])
                self.qname.append(buf[i + 1 : i + 1 + length].decode("utf-8"))
                i += length + 1
            self.bqnamecomplete = buf[:i]
            self.qtype = QuestionTypeEnum(int.from_bytes(buf[i : i + 2]))
            self.qclass = QuestionClassEnum(int.from_bytes(buf[i + 2 :]))

        def __repr__(self):
            return (
            f"Question(qname={self.qname}, bqname={self.bqname}, "
            f"bqnamecomplete={self.bqnamecomplete}, qtype={self.qtype}, qclass={self.qclass})"
            )

    def __init__(self, buf: bytes, qdcount: int):
        self.buf = buf
        self.questions = []
        for i in range(qdcount):
            offset = self.buf.find(b"\x00") + 5
            question = self.buf[:offset]
            self.questions.append(Questions.Question(question))
            self.buf = self.buf[offset:]
        self.buf = buf  # reset buf

    def __repr__(self):
        return f"Questions(questions={self.questions})"


class AnswerSection:
    def __init__(self, buf: bytes):
        self.name = buf[0:2]
        self.type = buf[2:4]
        self.class_ = buf[4:6]
        self.ttl = buf[6:10]
        self.rdlength = buf[10:12]
        self.rdata = buf[12:14]
        print(self.name)
        print(self.type)
        print(self.class_)
        print(self.ttl)
        print(self.rdlength)
        print(self.rdata)


class AuthoritySection:
    def __init__(self, buf: bytes):
        self.name = buf[0:2]
        self.type = buf[2:4]
        self.class_ = buf[4:6]
        self.ttl = buf[6:10]
        self.rdlength = buf[10:12]
        self.rdata = buf[12:14]
        print(self.name)
        print(self.type)
        print(self.class_)
        print(self.ttl)
        print(self.rdlength)
        print(self.rdata)


class AdditionalSection:
    def __init__(self, buf: bytes):
        self.name = buf[0:2]
        self.type = buf[2:4]
        self.class_ = buf[4:6]
        self.ttl = buf[6:10]
        self.rdlength = buf[10:12]
        self.rdata = buf[12:14]
        print(self.name)
        print(self.type)
        print(self.class_)
        print(self.ttl)
        print(self.rdlength)
        print(self.rdata)


class Packet:
    def __init__(self, buf: bytes):
        self.buf = buf
        self.header = Header(buf[0:12])
        self.questions = Questions(self.buf[12:], self.header.qdcount)
        # self.answer_section = AnswerSection(buf[24:36])
        # self.authority_section = AuthoritySection(buf[36:48])
        # self.additional_section = AdditionalSection(buf[48:60])

    def toByte(self) -> bytes:
        self.buf = self.header.toByte() + self.buf[12:]
        return self.buf

    def __repr__(self):
        return f"Packet(header={self.header}, questions={self.questions})"


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(f"{buf[:12]}\nother{buf[12:]}")
            packet = Packet(buf=buf)
            print(packet)
            packet.header.change_header(HeaderFlags.QR)
            response: bytes = packet.toByte()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
