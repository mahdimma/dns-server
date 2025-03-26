import sys
import socket
import struct
from enum import Flag
import logging

DNS_HEADER_SIZE = 12


# Configure logging
logging.basicConfig(
    level=logging.DEBUG, format="%(asctime)s - %(levelname)s - %(message)s"
)
logging.basicConfig(
    level=logging.ERROR, format="%(asctime)s - %(levelname)s - %(message)s"
)


class DNSResponse:
    class Packet:
        class HeaderFlag(Flag):
            QR = 0x8000  # Query/Response Flag
            AA = 0x0400  # Authoritative Answer
            TC = 0x0200  # Truncation
            RD = 0x0100  # Recursion Desired
            RA = 0x0080  # Recursion Available
            Z = 0x0040  # Reserved
            AD = 0x0020  # Authentic Data
            CD = 0x0010  # Checking Disabled

        def __init__(self, data: bytes):
            self.data = data
            self.parse()

        def parse(self):
            # Implement packet parsing logic here
            # Unpack the DNS header
            header = struct.unpack("!6H", self.data[:DNS_HEADER_SIZE])
            self.id = header[0]
            self.flags = header[1]
            self.qdcount = header[2]
            self.ancount = header[3]
            self.nscount = header[4]
            self.arcount = header[5]
            self.questions, self.qOffset = self.extract_questions(
                self.data, self.qdcount
            )
            self.answers, self.aOffset = self.extract_answer_section(
                self.data, self.ancount, self.qOffset
            )

        def extract_questions(self, data, qdcount):
            """
            Given the raw DNS packet and question count, extract the question section.
            Returns a list of raw question bytes and the offset after the question section.
            """
            questions = []
            offset = DNS_HEADER_SIZE
            for _ in range(qdcount):
                start = offset
                # Parse QNAME: series of labels ending with zero-length label.
                while offset < len(data) and data[offset] != 0 and data[offset] != 192:
                    label_length = data[offset]
                    offset += 1 + label_length  # skip length byte and the label
                if data[offset] == 0:
                    offset += 1  # skip the 0 byte that terminates QNAME
                    # Skip QTYPE and QCLASS (4 bytes)
                    offset += 4
                    questions.append(data[start:offset])
                else:
                    questions.append(
                        data[start:offset]
                        + self.extract_labels(data, data[offset + 1])
                        + data[offset + 2 : offset + 6]
                    )
                    offset += (
                        2  # skip the 192(c0) and offset byte that terminates QNAME
                    )
                    # Skip QTYPE and QCLASS (4 bytes)
                    offset += 4
            return questions, offset

        def extract_answer_section(self, data, ancount, qOffset):
            """
            Given a full DNS response packet, extract the answer section.
            Returns a list of raw answer bytes and the offset after the answer section.
            """
            answers = []
            offset = qOffset
            for _ in range(ancount):
                start = offset
                # Skip NAME (2 bytes if it's a pointer)
                while offset < len(data) and data[offset] != 0 and data[offset] != 192:
                    label_length = data[offset]
                    offset += 1 + label_length  # skip length byte and the label
                if data[offset] == 0:
                    # Skip TYPE, CLASS, TTL (8 bytes), and RDLENGTH (2 bytes) and zero(end of labels)
                    offset += 11
                    rdlength = struct.unpack("!H", data[offset - 2 : offset])[0]
                    # Extract RDATA
                    offset += rdlength
                    answers.append(data[start:offset])
                else:
                    pOffset = offset  # offset of pointer
                    # Skip TYPE, CLASS, TTL (8 bytes), and RDLENGTH (2 bytes) and pointer_offset
                    offset += 12
                    rdlength = struct.unpack("!H", data[offset - 2 : offset])[0]
                    # Extract RDATA
                    offset += rdlength
                    answers.append(
                        data[start:pOffset]
                        + self.extract_labels(data, pOffset)
                        + data[pOffset + 2 : offset]
                    )
            return answers, offset

        def extract_labels(self, buf, start):
            """
            Extract labels from the DNS packet starting at the given index.
            Returns the list of labels and the offset after the labels.
            """
            offset = start
            while buf[offset] != 0:
                label_length = buf[offset]
                offset += 1 + label_length
            offset += 1  # skip the 0 byte that terminates the labels
            return buf[start:offset]

        def changeHeaderFlags(
            self, headerFlag: HeaderFlag, opcode: int = 0, rcode: int = 0
        ):
            """
            Change the DNS header flags.
            """
            self.flags &= 0
            self.flags = headerFlag.value | (opcode << 11) | rcode

        def createAnswer(self, question, ttl, rdata):
            """
            Create a DNS answer for the given question.
            """
            # Extract QNAME, QTYPE, and QCLASS from the question
            qname_end = question.find(b"\x00")
            qname = question[: qname_end + 1]
            qtype, qclass = struct.unpack(
                "!HH", question[qname_end + 1 : qname_end + 5]
            )

            # Create a answer
            name = qname
            type_ = qtype
            class_ = qclass
            ttl = ttl  # Time to live
            rdlength = len(rdata)  # Length of the RDATA field
            rdata = rdata  # Convert IP address to bytes

            # Pack the answer in the DNS answer format
            answer = (
                name
                + struct.pack(
                    "!HHIH",
                    type_,
                    class_,
                    ttl,
                    rdlength,
                )
                + rdata
            )
            self.answers.append(answer)
            self.ancount += 1

        def toBytes(self):
            """
            Convert the DNS packet to bytes.
            """
            header = struct.pack(
                "!6H",
                self.id,
                self.flags,
                self.qdcount,
                self.ancount,
                self.nscount,
                self.arcount,
            )
            return header + b"".join(self.questions) + b"".join(self.answers)

        def __repr__(self):
            return (
                f"<DNSResponse.Packet id={self.id} flags={self.flags} "
                f"qdcount={self.qdcount} ancount={self.ancount} "
                f"nscount={self.nscount} arcount={self.arcount} "
                f"questions={self.questions} answers={self.answers}>"
            )

        def __str__(self):
            """
            Return a human-readable string representation of the DNS packet with ASCII colorized output.
            """

            class Color:
                HEADER = "\033[96m"
                QUESTION = "\033[93m"
                ANSWER = "\033[92m"
                END = "\033[0m"

            flags = [flag.name for flag in self.HeaderFlag if self.flags & flag.value]
            questions_str = "\n".join(
                [
                    f"{Color.QUESTION}Question {i + 1}:{Color.END} {self.format_question(q)}"
                    for i, q in enumerate(self.questions)
                ]
            )
            answers_str = "\n".join(
                [
                    f"{Color.ANSWER}Answer {i + 1}:{Color.END} {self.format_answer(a)}"
                    for i, a in enumerate(self.answers)
                ]
            )
            return (
                f"{Color.HEADER}DNS Packet:{Color.END}\n"
                f"{Color.HEADER}ID:{Color.END} {self.id}\n"
                f"{Color.HEADER}Flags:{Color.END} {', '.join(flags)}\n"
                f"{Color.HEADER}Questions Count:{Color.END} {self.qdcount}\n"
                f"{Color.HEADER}Answers Count:{Color.END} {self.ancount}\n"
                f"{Color.HEADER}Name Servers Count:{Color.END} {self.nscount}\n"
                f"{Color.HEADER}Additional Records Count:{Color.END} {self.arcount}\n"
                f"{Color.HEADER}Questions:{Color.END}\n{questions_str}\n"
                f"{Color.HEADER}Answers:{Color.END}\n{answers_str}"
            )

        def format_question(self, question):
            """
            Format a DNS question for readability.
            """
            qname_parts = []
            offset = 0
            while question[offset] != 0:
                length = question[offset]
                qname_parts.append(question[offset + 1 : offset + 1 + length].decode())
                offset += length + 1
            qname = ".".join(qname_parts)
            qtype, qclass = struct.unpack("!HH", question[offset + 1 : offset + 5])
            return f"QNAME: {qname}, QTYPE: {qtype}, QCLASS: {qclass}"

        def format_answer(self, answer):
            """
            Format a DNS answer for readability.
            """
            name_parts = []
            offset = 0
            while answer[offset] != 0:
                length = answer[offset]
                name_parts.append(answer[offset + 1 : offset + 1 + length].decode())
                offset += length + 1
            name = ".".join(name_parts)
            type_, class_, ttl, rdlength = struct.unpack(
                "!HHIH", answer[offset + 1 : offset + 11]
            )
            rdata = answer[offset + 11 : offset + 11 + rdlength]
            return f"NAME: {name}, TYPE: {type_}, CLASS: {class_}, TTL: {ttl}, RDLENGTH: {rdlength}, RDATA: {rdata}"

    def __init__(self, data: bytes):
        self.data = data
        self.packet = self.Packet(data)

    def process_response(self, address=None, port=None):
        logging.info(f"request: {self.packet}")
        if address and port:
            response = self.forwardQuery(address=address, port=port)
        else:
            response = self.process_response_locally()
        logging.info(f"response: {self.Packet(response)}")
        return response

    def process_response_locally(self):
        # Implement response processing logic here
        if (self.packet.flags >> 11) == 0:
            self.packet.changeHeaderFlags(
                self.Packet.HeaderFlag(
                    self.Packet.HeaderFlag.RD.value & self.packet.flags
                )
                | self.Packet.HeaderFlag.QR
            )
        else:
            self.packet.changeHeaderFlags(
                self.Packet.HeaderFlag(
                    self.Packet.HeaderFlag.RD.value & self.packet.flags
                )
                | self.Packet.HeaderFlag.QR,
                opcode=self.packet.flags >> 11,
                rcode=4,
            )
        for question in self.packet.questions:
            self.packet.createAnswer(question, 60, b"\x08\x08\x08\x08")
        return self.packet.toBytes()

    def forwardQuery(self, address, port):
        """
        Forward the DNS query to the specified address and port for each question
        and merge the responses.
        """
        for question in self.packet.questions:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
                header = struct.pack(
                    "!6H",
                    self.packet.id,
                    self.packet.flags,
                    1,
                    0,
                    self.packet.nscount,
                    self.packet.arcount,
                )
                sock.sendto(header + question, (address, port))
                sock.settimeout(5)  # Set a timeout for the response
                try:
                    response, _ = sock.recvfrom(512)  # Receive the response
                    if response:
                        # Merge the answers from the response
                        response_packet = self.Packet(response)
                        response_packet.parse()
                        self.packet.answers.extend(response_packet.answers)
                        self.packet.ancount += response_packet.ancount
                except socket.timeout:
                    logging.error("Request timed out for question:", question)
        if (self.packet.flags >> 11) == 0:
            self.packet.changeHeaderFlags(
                self.Packet.HeaderFlag(
                    self.Packet.HeaderFlag.RD.value & self.packet.flags
                )
                | self.Packet.HeaderFlag.QR
            )
        else:
            self.packet.changeHeaderFlags(
                self.Packet.HeaderFlag(
                    self.Packet.HeaderFlag.RD.value & self.packet.flags
                )
                | self.Packet.HeaderFlag.QR,
                opcode=self.packet.flags >> 11,
                rcode=4,
            )
        return self.packet.toBytes()


def main():
    address = port = None
    if len(sys.argv) == 3:
        address, port = sys.argv[2].split(":")
        port = int(port)
    if address and port:
        logging.info(f"Forwarding DNS queries to {address}:{port}")
    logging.info("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            logging.info("Starting DNS server...")
            buf, source = udp_socket.recvfrom(512)
            if address:
                response = DNSResponse(buf).process_response(address=address, port=port)
            else:
                response = DNSResponse(buf).process_response()
            udp_socket.sendto(response, source)
        except Exception as e:
            logging.error(f"Error receiving data: {e}")


if __name__ == "__main__":
    main()
