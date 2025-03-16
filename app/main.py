import socket


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

    def change_header(
        self,
        qr: int = None,
        OPCODE: int = None,
        AA: int = None,
        TC: int = None,
        RD: int = None,
        RA: int = None,
        Z: int = None,
        RCODE: int = None,
    ) -> None:
        if qr is not None:
            self.qr = qr
        if OPCODE is not None:
            self.OPCODE = OPCODE
        if AA is not None:
            self.AA = AA
        if TC is not None:
            self.TC = TC
        if RD is not None:
            self.RD = RD
        if RA is not None:
            self.RA = RA
        if Z is not None:
            self.Z = Z
        if RCODE is not None:
            self.RCODE = RCODE

        self.flags = (
            (self.qr << 15)
            | (self.OPCODE << 11)
            | (self.AA << 10)
            | (self.TC << 9)
            | (self.RD << 8)
            | (self.RA << 7)
            | (self.Z << 4)
            | self.RCODE
        )

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


class Question:
    def __init__(self, buf: bytes):
        self.qname = buf[0:2]
        self.qtype = buf[2:4]
        self.qclass = buf[4:6]
        print(self.qname)
        print(self.qtype)
        print(self.qclass)


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
        # self.question = Question(buf[12:24])
        # self.answer_section = AnswerSection(buf[24:36])
        # self.authority_section = AuthoritySection(buf[36:48])
        # self.additional_section = AdditionalSection(buf[48:60])

    def toByte(self) -> bytes:
        self.buf = self.header.toByte() + self.buf[12:]
        return self.buf


def main():
    # You can use print statements as follows for debugging, they'll be visible when running tests.
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)

            packet = Packet(buf=buf)
            packet.header.change_header(
                qr=1, OPCODE=0, AA=0, TC=0, RD=0, RA=0, Z=0, RCODE=0
            )
            response: bytes = packet.toByte()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
