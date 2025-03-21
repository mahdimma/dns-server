import socket
from enum import Flag, Enum


class Packet:
    class PacketType(Enum):
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

    class PacketClass(Enum):
        IN = 1
        CS = 2
        CH = 3
        HS = 4

    class Header:
        class HeaderFlags(Flag):
            QR = 0x8000
            OPCODE = 0x7800
            AA = 0x0400
            TC = 0x0200
            RD = 0x0100
            RA = 0x0080
            Z = 0x0040  # Reserved for future use, must be zero in all queries and responses
            AD = 0x0020  # Authenticated Data
            CD = 0x0010  # Checking Disabled
            RCODE = 0x000F

        def __init__(self, buf: bytes):
            self.buf = buf
            self.id = int.from_bytes(buf[0:2], byteorder="big")
            self.flags = int.from_bytes(buf[2:4], byteorder="big")
            self.qr = (self.flags & self.HeaderFlags.QR.value) >> 15
            self.OPCODE = (self.flags & self.HeaderFlags.OPCODE.value) >> 11
            self.AA = (self.flags & self.HeaderFlags.AA.value) >> 10
            self.TC = (self.flags & self.HeaderFlags.TC.value) >> 9
            self.RD = (self.flags & self.HeaderFlags.RD.value) >> 8
            self.RA = (self.flags & self.HeaderFlags.RA.value) >> 7
            self.Z = (self.flags & self.HeaderFlags.Z.value) >> 6
            self.AD = (self.flags & self.HeaderFlags.AD.value) >> 5
            self.CD = (self.flags & self.HeaderFlags.CD.value) >> 4
            self.RCODE = self.flags & self.HeaderFlags.RCODE.value
            self.qdcount = int.from_bytes(buf[4:6], byteorder="big")
            self.ancount = int.from_bytes(buf[6:8], byteorder="big")
            self.nscount = int.from_bytes(buf[8:10], byteorder="big")
            self.arcount = int.from_bytes(buf[10:12], byteorder="big")

        def change_header(
            self, flag: HeaderFlags, opcode: int = 0, rcode: int = 0
        ) -> None:
            """
            Modify the DNS header flags and related attributes.

            This method updates the DNS header flags based on the provided flag, opcode, and rcode.
            It also sets various attributes of the DNS header based on the updated flags.

            Args:
                flag (HeaderFlags): The header flag to set.
                opcode (int, optional): The operation code to set. Defaults to 0.
                rcode (int, optional): The response code to set. Defaults to 0.

            Returns:
                None
            """
            self.flags = flag.value | (opcode << 11) | rcode
            self.qr = (self.flags & self.HeaderFlags.QR.value) >> 15
            self.OPCODE = opcode
            self.AA = (self.flags & self.HeaderFlags.AA.value) >> 10
            self.TC = (self.flags & self.HeaderFlags.TC.value) >> 9
            self.RD = (self.flags & self.HeaderFlags.RD.value) >> 8
            self.RA = (self.flags & self.HeaderFlags.RA.value) >> 7
            self.Z = (self.flags & self.HeaderFlags.Z.value) >> 6
            self.AD = (self.flags & self.HeaderFlags.AD.value) >> 5
            self.CD = (self.flags & self.HeaderFlags.CD.value) >> 4
            self.RCODE = rcode

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
                f"AA={self.AA}, TC={self.TC}, RD={self.RD}, RA={self.RA}, Z={self.Z}, AD={self.AD}, CD={self.CD}, RCODE={self.RCODE}, "
                f"qdcount={self.qdcount}, ancount={self.ancount}, nscount={self.nscount}, arcount={self.arcount})"
            )

    class Questions:
        class Question:
            def __init__(self, buf: bytes):
                self.qname: list[str] = []
                self.bqname: list[bytes] = []
                self.bqnamecomplete: bytes = b""
                self.qtype: Packet.PacketType = None
                self.qclass: Packet.PacketClass = None
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
                self.qtype = Packet.PacketType(int.from_bytes(buf[i : i + 2]))
                self.qclass = Packet.PacketClass(int.from_bytes(buf[i + 2 :]))

            def __repr__(self):
                return (
                    f"Question(qname={self.qname}, bqname={self.bqname}, "
                    f"bqnamecomplete={self.bqnamecomplete}, qtype={self.qtype}, qclass={self.qclass})"
                )

        def __init__(self, buf: bytes, qdcount: int):
            self.buf = buf
            self.questions = []
            self.length = 0
            for i in range(qdcount):
                offset = self.buf.find(b"\x00", self.length) + 5
                question = self.buf[
                    self.length : offset
                ]  # length work like preOffset and in end set to full length
                self.questions.append(self.Question(question))
                self.length = offset
                print(self.length)

        def __repr__(self):
            return f"Questions(questions={self.questions})"

    class AnswerSection:
        class Answer:
            def __init__(self, question):  # type
                self.baname: bytes = question.bqnamecomplete
                self.aname: list[str] = question.qname
                self.atype: Packet.PacketType = question.qtype
                self.aclass: Packet.PacketClass = question.qclass
                self.ttl: int = 60
                self.length: int = 4
                self.data: list[str] = [8, 8, 8, 8]

            def toBytes(self) -> bytes:
                return (
                    self.baname
                    + self.atype.value.to_bytes(2, "big")
                    + self.aclass.value.to_bytes(2, "big")
                    + self.ttl.to_bytes(4, "big")
                    + self.length.to_bytes(2, "big")
                    + b"".join(
                        [
                            x.to_bytes(1, "big")
                            if isinstance(x, int)
                            else x.encode(encoding="ascii")
                            for x in self.data
                        ]
                    )
                )

            def __repr__(self):
                return (
                    f"Answer(baname={self.baname}, aname={self.aname}, atype={self.atype}, "
                    f"aclass={self.aclass}, ttl={self.ttl}, length={self.length}, "
                    f"data={self.data})"
                )

        def __init__(self, questions, ancount):  # type
            self.questions = questions
            self.answers = []
            self.bAnswers = []
            self.createAnswers()

        def createAnswers(self):
            for question in self.questions:
                self.answers.append(self.Answer(question=question))
            for answer in self.answers:
                self.bAnswers.append(answer.toBytes())

        def toByets(self):
            return b"".join(self.bAnswers)

        def __repr__(self):
            return f"Answers(answers={self.answers})"

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

    def __init__(self, buf: bytes):
        self.buf = buf
        self.header = self.Header(buf[0:12])
        self.header.ancount = self.header.qdcount
        self.questions = self.Questions(self.buf[12:], self.header.qdcount)
        self.answer_section = None
        # self.authority_section = AuthoritySection(buf[36:48])
        # self.additional_section = AdditionalSection(buf[48:60])

    def toByte(self) -> bytes:
        print(f"to byte: {self.questions.length} ")
        print(
            f"{self.header.toByte()} - {self.buf[12 : 12 + self.questions.length]} --- {self.answer_section.toByets()} ---- {self.buf[self.questions.length + 12 :]}"
        )
        return (
            self.header.toByte()
            + self.buf[12 : 12 + self.questions.length]
            + self.answer_section.toByets()
            + self.buf[12 + self.questions.length :]
        )

    def response(self):
        self.answer_section = self.AnswerSection(
            self.questions.questions, self.header.ancount
        )
        if self.header.OPCODE == 0:
            if self.header.RD == 1:
                self.header.change_header(
                    self.header.HeaderFlags.QR | self.header.HeaderFlags.RD
                )
            else:
                self.header.change_header(self.header.HeaderFlags.QR)
        else:
            if self.header.RD == 1:
                self.header.change_header(
                    self.header.HeaderFlags.QR | self.header.HeaderFlags.RD,
                    opcode=self.header.OPCODE,
                    rcode=4,
                )
            else:
                self.header.change_header(
                    self.header.HeaderFlags.QR,
                    opcode=self.header.OPCODE,
                    rcode=4,
                )

        return self

    def __repr__(self):
        return f"Packet(header={self.header}, questions={self.questions}, answer={self.answer_section})"


def main():
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            buf, source = udp_socket.recvfrom(512)
            print(
                f"\n\nbuffer reading...\n{buf[:12]}\nother{buf[12:]}\nbuffer reading end.\n"
            )
            packet = Packet(buf=buf)
            print(packet)
            response: Packet = packet.response()
            print(f"\n\nresponse: {response}\n\n---packet process end---")
            bresponse: bytes = response.toByte()
            print(
                f"\n\nbresponse reading...\n{bresponse[:12]}\nother{bresponse[12:]}\nbuffer reading end.\n\n\n"
            )
            udp_socket.sendto(bresponse, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
