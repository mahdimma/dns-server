import socket
from enum import Flag, Enum
import sys


class Color(Enum):
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    RESET = "\033[0m"


def printc(text, color: Color):
    print(f"{color.value}{text}{Color.RESET.value}")


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
            def __init__(
                self,
                buf: bytes,
                labels: dict,
                start: int,
                end: int = None,
                first: bool = True,
            ):
                self.qname: list[str] = []
                self.bqname: list[bytes] = []
                self.bqnamecomplete: bytes = b""
                self.qtype: Packet.PacketType = None
                self.qclass: Packet.PacketClass = None
                self.buf = buf
                i = start
                if first:
                    while True:
                        print(f"buf: {i}, {buf[i:]}")
                        length = buf[i]
                        if length == 0:
                            i += 1
                            break
                        self.bqname.append(buf[i + 1 : i + 1 + length])
                        self.qname.append(buf[i + 1 : i + 1 + length].decode("utf-8"))
                        i += length + 1
                    self.bqnamecomplete = buf[start:i]
                    print(self.bqnamecomplete)
                    self.qtype = Packet.PacketType(int.from_bytes(buf[i : i + 2]))
                    self.qclass = Packet.PacketClass(
                        int.from_bytes(buf[i + 2 : end + 1])
                    )
                else:
                    while True:
                        signer = int(buf[i])
                        print(f"buf bef sign: {i}, {buf[i]} C0?")

                        if signer >= 192:
                            print(f"buf: {i}, {buf[i]} C0?")
                            offset = int.from_bytes(buf[i : i + 2], "big") - 49152
                            bqname, qname, bqnamecomplete = self.parse(buf[offset:])
                            self.bqname += bqname
                            self.qname += qname
                            self.bqnamecomplete += bqnamecomplete
                            i += 2
                            break
                        elif signer == 0:
                            i += 1
                            break
                        self.bqname.append(buf[i + 1 : i + 1 + signer])
                        self.qname.append(buf[i + 1 : i + 1 + signer].decode("utf-8"))
                        i += signer + 1
                    self.bqnamecomplete = buf[start:i]
                    self.qtype = Packet.PacketType(int.from_bytes(buf[i : i + 2]))
                    self.qclass = Packet.PacketClass(int.from_bytes(buf[i + 2 : i + 4]))
                self.i = i
                printc(f"i in question: {i}, {buf[i : i + 5]}", Color.CYAN)

            def __repr__(self):
                return (
                    f"Question(qname={self.qname}, bqname={self.bqname}, "
                    f"bqnamecomplete={self.bqnamecomplete}, qtype={self.qtype}, qclass={self.qclass})"
                )

            def parse(self, buf) -> tuple[list[bytes], list[str], bytes]:
                i = 0
                bqname = []
                qname = []
                while True:
                    length = buf[i]
                    if length == 0:
                        break
                    elif length >= 192:
                        break
                    bqname.append(buf[i + 1 : i + 1 + length])
                    qname.append(buf[i + 1 : i + 1 + length].decode("utf-8"))
                    i += length + 1
                bqnamecomplete = buf[:i]
                print(f"parser: {bqname, qname, bqnamecomplete}")
                return bqname, qname, bqnamecomplete

            def toBytes(self):
                question = b""
                for label in self.bqname:
                    question += bytes([len(label)]) + label
                return (
                    question
                    + b"\x00"
                    + self.qtype.value.to_bytes(2, "big")
                    + self.qclass.value.to_bytes(2, "big")
                )

        def __init__(self, buf: bytes, qdcount: int):
            self.buf = buf
            self.questions = []
            self.labels = {}
            self.length = 12
            offset = self.buf.find(b"\x00", self.length) + 5
            self.questions.append(
                self.Question(self.buf, self.labels, start=self.length, end=offset - 1)
            )
            self.length = offset
            print(f"len....{self.length}")
            for i in range(qdcount - 1):
                self.questions.append(
                    self.Question(self.buf, self.labels, self.length, first=False)
                )
                self.length = self.questions[-1].i + 4
                print("packet Q: ", i, self.length)

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
                self.data: bytes = b"\x08\x08\x08\x08"

            def toBytes(self) -> bytes:
                return (
                    self.baname
                    + self.atype.value.to_bytes(2, "big")
                    + self.aclass.value.to_bytes(2, "big")
                    + self.ttl.to_bytes(4, "big")
                    + self.length.to_bytes(2, "big")
                    + self.data
                )

            def __repr__(self):
                return (
                    f"Answer(baname={self.baname}, aname={self.aname}, atype={self.atype}, "
                    f"aclass={self.aclass}, ttl={self.ttl}, length={self.length}, "
                    f"data={self.data})"
                )

            def parse(self, buf) -> tuple[list[bytes], list[str], bytes]:
                i = 0
                bqname = []
                qname = []
                while True:
                    length = buf[i]
                    if length == 0:
                        break
                    elif length >= 192:
                        break
                    bqname.append(buf[i + 1 : i + 1 + length])
                    qname.append(buf[i + 1 : i + 1 + length].decode("utf-8"))
                    i += length + 1
                bqnamecomplete = buf[:i]
                print(f"parser: {bqname, qname, bqnamecomplete}")
                return bqname, qname, bqnamecomplete

            def readAnswer(
                self,
                buf: bytes,
                labels,
                start,
                end: int = None,
                first: bool = True,
            ):
                self.aname: list[str] = []
                self.baname: list[bytes] = []
                self.banamecomplete: bytes = b""
                self.atype: Packet.PacketType = None
                self.aclass: Packet.PacketClass = None
                self.buf = buf
                i = start
                if first:
                    while True:
                        printc(f"buf: {i}, {buf[i - 3 :]}", Color.YELLOW)
                        print(buf[i])
                        length = buf[i]
                        if length == 0:
                            i += 1
                            break
                        self.baname.append(buf[i + 1 : i + 1 + length])
                        self.aname.append(buf[i + 1 : i + 1 + length].decode("utf-8"))
                        i += length + 1
                    self.banamecomplete = buf[start:i]
                    print(self.banamecomplete)
                    self.atype = Packet.PacketType(int.from_bytes(buf[i : i + 2]))
                    self.aclass = Packet.PacketClass(int.from_bytes(buf[i + 2 : i + 4]))
                    self.ttl = int.from_bytes(buf[i + 4 : i + 8])
                    self.length = int.from_bytes(buf[i + 8 : i + 10])
                    self.data = buf[i + 10 : i + 10 + self.length]
                else:
                    while True:
                        signer = int(buf[i])
                        print(f"buf bef sign: {i}, {buf[i]} C0?")

                        if signer >= 192:
                            print(f"buf: {i}, {buf[i]} C0?")
                            offset = int.from_bytes(buf[i : i + 2], "big") - 49152
                            baname, aname, banamecomplete = self.parse(buf[offset:])
                            self.baname += baname
                            self.aname += aname
                            self.banamecomplete += banamecomplete
                            i += 2
                            break
                        elif signer == 0:
                            i += 1
                            break
                        self.baname.append(buf[i + 1 : i + 1 + signer])
                        self.aname.append(buf[i + 1 : i + 1 + signer].decode("utf-8"))
                        i += signer + 1
                    self.bqnamecomplete = buf[start:i]
                    self.atype = Packet.PacketType(int.from_bytes(buf[i : i + 2]))
                    self.aclass = Packet.PacketClass(int.from_bytes(buf[i + 2 : i + 4]))
                    self.ttl = int.from_bytes(buf[i + 4 : i + 8])
                    self.length = int.from_bytes(buf[i + 8 : i + 10])
                    self.data = buf[i + 10 : i + 10 + self.length]
                self.i = i + 10 + self.length
                return self

        def __init__(
            self, questions, buf: bytes = b"", start: int = 0, ancount: int = 0
        ):  # type
            self.questions = questions
            self.answers = []
            self.bAnswers = []
            printc(f"ancount is ****: {ancount}", Color.RED)
            if ancount == 0:
                self.createAnswers()
            else:
                self.readAnswers(buf, start, ancount)

        def createAnswers(self):
            for question in self.questions:
                self.answers.append(self.Answer(question=question))
            for answer in self.answers:
                self.bAnswers.append(answer.toBytes())

        def readAnswers(self, buf, start, ancount):
            self.buf = buf
            self.answers = []
            self.labels = {}
            self.length = start
            self.answers.append(
                self.Answer(self.questions[0]).readAnswer(
                    self.buf, self.labels, start=self.length
                )
            )
            self.length = self.answers[-1].i
            print(f"Answer...len....{self.length}")
            for i in range(ancount - 1):
                self.answers.append(
                    self.Answer(self.questions[0]).readAnswer(
                        self.buf, self.labels, self.length, first=False
                    )
                )
                self.length = self.answers[-1].i
                print("packet A: ", i, self.length)

        def toByets(self):
            return b"".join(self.bAnswers)

        def __repr__(self):
            return f"Answers(answers={self.answers})"

    class AuthoritySection:
        def __init__(self, buf: bytes):
            pass

    class AdditionalSection:
        def __init__(self, buf: bytes):
            pass

    def __init__(self, buf: bytes):
        self.buf = buf
        self.header = self.Header(buf[0:12])
        printc(f"self header is {self.header}", Color.MAGENTA)
        self.questions = None
        self.answer_section = None
        if self.header.RCODE == 4:
            return
        self.questions = self.Questions(self.buf, self.header.qdcount)
        if self.header.ancount > 0:
            self.answer_section = self.AnswerSection(
                self.questions.questions,
                buf=self.buf,
                start=self.questions.length,
                ancount=self.header.ancount,
            )
        # self.authority_section = AuthoritySection(buf[36:48])
        # self.additional_section = AdditionalSection(buf[48:60])

    def toByte(self) -> bytes:
        if self.answer_section:
            print(f"in to bytes: {self}")
            print(f"to byte: {self.questions.length} ")
            return (
                self.header.toByte()
                + self.buf[12 : self.questions.length]
                + self.answer_section.toByets()
                + self.buf[self.questions.length :]
            )
        return self.header.toByte() + self.buf[12:]

    def response(self):
        self.header.ancount = self.header.qdcount
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

    def forwardResponse(self, adderss, port):
        printc("in forward mod: ", Color.RED)
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
        self.header.ancount = self.header.qdcount
        if len(self.questions.questions) > 1:
            answers = []
            for question in self.questions.questions:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                    header = Packet(self.buf).header
                    header.qdcount = 1
                    header = header.toByte()
                    printc(
                        f"each packet: {Packet(header + question.toBytes())}", Color.RED
                    )
                    printc(header + question.toBytes(), Color.RED)
                    sock.sendto(header + question.toBytes(), (adderss, port))
                    response, _ = sock.recvfrom(1024)
                    printc(f"recive{response}", Color.RED)
                    answers.append(response[len(header + question.toBytes()) :])
            print(answers)
            self.buf = self.header.toByte() + self.buf[12:]
            answer = self.buf + b"".join(answers)
            printc(f"last answer in multi: {answer}", color=Color.MAGENTA)
            return Packet(answer)
        else:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                print(f"self buf: {self.buf}")
                sock.sendto(self.buf, (adderss, port))
                response, _ = sock.recvfrom(1024)
                printc(
                    f"forward response: {response}",
                    color=Color.RED,
                )
                printc({Packet(response)}, Color.BLACK)
                return Packet(response)

    def __repr__(self):
        return f"Packet(header={self.header}, questions={self.questions}, answer={self.answer_section})"


def main():
    adderss = port = None
    if len(sys.argv) == 3:
        adderss, port = sys.argv[2].split(":")
        port = int(port)
    if adderss and port:
        print(f"Forwarding DNS queries to {adderss}:{port}")
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        # try:
        printc("Starting DNS server...", Color.YELLOW)
        buf, source = udp_socket.recvfrom(512)
        print(source)
        print(
            f"\n\nbuffer reading...\n{buf[:12]}\nother{buf[12:]}\nbuffer reading end.\n"
        )
        packet = Packet(buf=buf)
        print(f"in main {packet}")
        if adderss:
            response: Packet = packet.forwardResponse(adderss, port)
        else:
            response: Packet = packet.response()
        print(f"\n\nresponse: {response}\n\n---packet process end---")
        bresponse: bytes = response.toByte()
        print(
            f"\n\nbresponse reading...\n{bresponse[:12]}\nother{bresponse[12:]}\nbuffer reading end.\n\n\n"
        )
        udp_socket.sendto(bresponse, source)
        printc("ended", Color.YELLOW)
    # except Exception as e:
    #     print(f"Error receiving data: {e}")
    #     break


if __name__ == "__main__":
    main()
