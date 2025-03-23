import sys
import socket
import struct
from enum import Flag

DNS_HEADER_SIZE = 12


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
                    # Skip TYPE, CLASS, TTL (8 bytes), and RDLENGTH (2 bytes)
                    offset += 10
                    rdlength = struct.unpack("!H", data[offset - 2 : offset])[0]
                    # Extract RDATA
                    offset += rdlength
                    answers.append(data[start:offset])
                else:
                    pOffset = offset  # offset of pointer
                    # Skip TYPE, CLASS, TTL (8 bytes), and RDLENGTH (2 bytes)
                    offset += 11
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

    def __init__(self, data: bytes):
        self.data = data
        self.packet = self.Packet(data)

    def process_response(self, address=None, port=None):
        if address and port:
            return self.forwardQuery(address=address, port=port)
        else:
            return self.process_response_locally()

    def process_response_locally(self):
        # Implement response processing logic here
        self.packet.parse()
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
        self.packet.parse()
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
                    print("Request timed out for question:", question)
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
        print(f"Forwarding DNS queries to {address}:{port}")
    print("Logs from your program will appear here!")

    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(("127.0.0.1", 2053))

    while True:
        try:
            print("Starting DNS server...")
            buf, source = udp_socket.recvfrom(512)
            if address:
                response = DNSResponse(buf).process_response(address=address, port=port)
            else:
                response = DNSResponse(buf).process_response()
            udp_socket.sendto(response, source)
        except Exception as e:
            print(f"Error receiving data: {e}")
            break


if __name__ == "__main__":
    main()
