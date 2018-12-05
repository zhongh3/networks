# to reload module:
# import imp
# imp.reload(module)


########################
# TCP ACK Packet
# 13:00:02.289911 IP 164.56.63.35.80 > 34.2.209.104.1088: . ack 1 win 65535 ----- 20 bytes (minimum size)
# 13:00:02.290217 IP 193.186.164.176.49158 > 198.14.23.145.8030: . ack 21682 win 3880
#   <nop,nop,timestamp 2510961092 106044096> ---- 32 bytes (with options)
########################


########################
# Packets with incomplete info. - excluded in size calculation
# e.g.
# 13:00:01.556764 IP truncated-ip - 19 bytes missing! 40.121.158.139 > 40.121.158.139: [|tcp]
# 13:00:01.626083 IP 220.9.185.142 > 183.128.232.79: udp
# 13:00:01.525604 IP 192.186.21.41 > 192.207.23.138: [|icmp]
########################

import matplotlib.pyplot as plt
import numpy as np
from enum import IntEnum
from scipy.special import factorial

import logging
# change logging level from INFO to DEBUG to print debugging logs
logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(funcName)s - %(lineno)d - %(message)s')


ip_header_size = 20  # 20 bytes
udp_header_size = 8  # 8 bytes


class TYPE(IntEnum):
    ICMP = 0
    UDP = 1
    TCP = 2


class TCPPacket:
    @staticmethod
    def get_packet_size(tcpdump):
        payload = TCPPacket.get_payload_size(tcpdump)
        header = TCPPacket.get_header_size(tcpdump)

        logging.debug("TCP packet size (incl. IP header) = {}".format(payload + header + ip_header_size))
        return payload + header + ip_header_size

    @staticmethod
    def get_payload_size(tcpdump):

        start = tcpdump.find("(")
        if start == -1:  # there's no payload information
            payload = 0
        else:
            end = tcpdump.find(")")
            if end - start < 2:
                raise Exception("Check this record: " + tcpdump)
            payload = int(tcpdump[start+1:end])

        logging.debug("TCP payload size = {}".format(payload))

        return payload

    @staticmethod
    def get_header_size(tcpdump):
        tcp_header_base = 20  # TCP header without option are 20 bytes

        start = tcpdump.find("<")
        if start == -1:  # there's no option
            option = 0   # 0 bytes
        else:
            end = tcpdump.find(">", start)
            if end <= start:
                raise Exception("Check this record: " + tcpdump)
            option = TCPPacket.process_tcp_options(tcpdump[start+1: end])

        logging.debug("TCP header size = {}".format(tcp_header_base + option))

        return tcp_header_base + option

    # ---------------------------------------------------
    # TCP Header Size without option - 20 bytes
    # TCP Options:
    # ---------------
    # Maximum Segment Size           mss       4 bytes
    # Window Scaling                 wscale    3 bytes
    # Selective Acknowledgements
    #   SACK-Permitted Option        sackOK    2 bytes
    #   SACK Option                       (4n+2) bytes (n is no. of block)
    #       e.g. "sack sack 1 {0:536}" -- 1 block
    # Timestamps                              10 bytes
    # No-Operation                   nop       1 byte
    # End of option list             eol       1 byte
    # Connection Count New           ccnew     6 byte
    # ---------------------------------------------------

    tcp_options = {
        "mss": 4,
        "wscale": 3,
        "sackOK": 2,
        # "sack sack": 4*n +2
        "timestamp": 10,
        "nop": 1,
        "eol": 1,
        "ccnew": 6,
        "[bad opt]": 0
    }

    @staticmethod
    def process_tcp_options(option):
        ops = option.strip().split(",")
        size = 0

        for op in ops:
            valid_option = False
            if "sack sack" in op:
                n = int(op.strip().split(" ")[2])
                size += 4 * n + 2
                valid_option = True
            else:
                for key in TCPPacket.tcp_options.keys():
                    if key in op:
                        size += TCPPacket.tcp_options[key]
                        valid_option = True
                        continue

            if not valid_option:
                raise Exception('Invalid TCP option in "{}"'.format(option))

        logging.debug("TCP option size = {}".format(size))

        return size


def read_input(input_file):
    f = open(input_file, 'r')
    records = [line.strip() for line in f]
    f.close()

    return records


def get_records(in_records, keyword):
    output = []

    for item in in_records:
        if keyword in item:
            output.append(item)

    logging.debug('In total {} records with keyword "{}".'.format(len(output), keyword))

    return output


def get_other_records(all_records):
    others = []

    for item in all_records:
        if "win" not in item and "UDP" not in item and "icmp " not in item:
            others.append(item)

    logging.debug('In total {} records without "win" or "UDP" or "icmp "'.format(len(others)))  # 10429

    # it includes packets with incomplete info.
    return others


def write_to_file(records, file_name):
    f = open(file_name, 'w')
    for item in records:
        f.write(item + "\n")

    f.close()

    print("output to file - {}".format(file_name))


def process_icmp(icmp):
    sizes = []

    for item in icmp:
        if "icmp " in item:
            start = item.find("icmp ") + len("icmp ")
            end = item.find(":", start)
            if end != -1 and item[start:end]:
                # the size is ICMP payload, including ICMP header (8 bytes), excluding IP header
                sizes.append(int(item[start:end]) + ip_header_size)

    logging.info("ICMP size: max = {}; min = {}".format(max(sizes), min(sizes)))

    return sizes


def process_upd(udp):
    sizes = []

    for item in udp:
        if "length: " in item:
            start = item.find("length: ") + len("length: ")
            if item[start:]:  # not empty string
                # the size is the UDP payload, excluding IP header and UDP header (8 bytes)
                sizes.append(int(item[start:]) + ip_header_size + udp_header_size)

    logging.info("UDP size: max = {}; min = {}".format(max(sizes), min(sizes)))

    return sizes


def process_tcp(tcp):
    sizes = [TCPPacket.get_packet_size(record) for record in tcp]
    # count_tcp_flags(tcp)

    logging.info("TCP size: max = {}; min = {}".format(max(sizes), min(sizes)))

    return sizes

# ---------------
# tcpdump Flags:
# ---------------
# TCP Flag	tcpdump Flag	Meaning
#   SYN	        S	        Syn packet, a session establishment request.
#   ACK	        A	        Ack packet, acknowledge sender’s data.
#   FIN	        F	        Finish flag, indication of termination.
#   RESET	    R	        Reset, indication of immediate abort of conn.
#   PUSH	    P	        Push, immediate push of data from sender.
#   URGENT	    U	        Urgent, takes precedence over other data.
#   NONE	  A dot .	    Placeholder, usually used for ACK.
#   ECE-Echo    E           ECN: Explicit Congestion Notification
#   ECN CWR     W           CWR: Congestion Window Reduced
# ------------------------------------------------------------------------------
# Tcpflags are some combination of S (SYN), F (FIN), P (PUSH), R (RST), U (URG),
# W (ECN CWR), E (ECN-Echo) or `.' (ACK), or `none' if no flags are set.
# ------------------------------------------------------------------------------


def count_tcp_flags(tcp):
    # Flag combinations (10): F, FP, FR, P, R, RP, RW, S, SWE, .,

    c_f = sum([": F " in item for item in tcp])      # 2992
    c_fp = sum([": FP " in item for item in tcp])    # 644
    c_fr = sum([": FR " in item for item in tcp])    # 1
    c_p = sum([": P " in item for item in tcp])      # 27097
    c_r = sum([": R " in item for item in tcp])      # 2889
    c_rp = sum([": RP " in item for item in tcp])    # 3
    c_rw = sum([": RW " in item for item in tcp])    # 4
    c_s = sum([": S " in item for item in tcp])      # 74444
    c_swe = sum([": SWE " in item for item in tcp])  # 1
    c_dot = sum([": . " in item for item in tcp])    # 74443

    logging.info("Flag combinations: F={}, FP={}, FR={}, P={}, R={}, RP={}, RW={}, S={}, SWE={}, .={}, Total={}"
                 .format(c_f, c_fp, c_fr, c_p, c_r, c_rp, c_rw, c_s, c_swe, c_dot,
                         c_f + c_fp + c_fr + c_p + c_r + c_rp + c_rw + c_s + c_swe + c_dot))

    if c_f + c_fp + c_fr + c_p + c_r + c_rp + c_rw + c_s + c_swe + c_dot != len(tcp):
        raise Exception("Some other TCP flag combinations exist.")

    # output = []
    # for item in tcp:
    #     if (": F " not in item) and (": FP " not in item) \
    #             and (": P " not in item) and (": R " not in item) \
    #             and (": S " not in item) and (": . " not in item) \
    #             and (": FR " not in item) and (": RW " not in item) and (": SWE " not in item):
    #         output.append(item)

    return c_p, c_s, c_dot  # the top 3 counts


def plot_poisson(mean, range):
    t = range
    d = np.exp(-mean) * np.power(mean, t) / factorial(t)

    label = "Poisson Distribution with Mean = " + str(mean)
    plt.plot(t, d, label=label)
    # plt.show()


def plot_exponential(mean, range):
    x = 1/mean
    t = np.asarray(range)
    d = x * np.exp(-x * t)

    label = "Exponential Distribution with Mean = " + str(mean)
    plt.plot(t, d, label=label)


def find_top_x_common_p_size(x, sizes):
    # find the values of top x counts, e.g. x = 5 --> top 5 counts

    # values are sorted in ascending order
    values, counts = np.unique(sizes, return_counts=True)

    top_counts = np.sort(counts)[::-1][0:x]
    out = []  # [count, value] pairs

    print("Top {} most common packet sizes:".format(x))
    for count in top_counts:
        idx = int(np.where([x == count for x in counts])[0])
        print("size = {} bytes  count = {}".format(values[idx], count))
        out.append([count, values[idx]])

    return out


def justify_poisson_arrival(all_records):

    inter_arrival = calculate_inter_arrival_times(all_records)

    values, counts = np.unique(inter_arrival, return_counts=True)

    print("Peak of interarrival time = {}, count = {}, prob = {}"
          .format(values[np.argmax(counts)], max(counts), max(counts)/sum(counts)))

    counts = counts/sum(counts)

    plt.plot(values[0:150], counts[0:150], label="Actual Packet Interarrival Time Distribution")
    plt.xlabel('interarrival time (us)')
    plt.ylabel('probability')

    mean = sum(inter_arrival)/len(inter_arrival)
    print("Mean of interarrival time = {}".format(mean))

    # plot_poisson(mean, values[0:150])
    plot_exponential(mean, values[0:150])

    plt.legend()
    plt.show()


def calculate_inter_arrival_times(all_records):
    # Timestamp of all packets are in the interval 13:00:00.642598 to 13:00:17.597013
    inter_arrival_times = [0]  # inter arrival time of 1st packet is 0

    t1 = parse_arrival_time(all_records[0])

    for p in all_records[1:]:
        t2 = parse_arrival_time(p)
        inter_arrival_times.append(t2 - t1)
        t1 = t2

    return inter_arrival_times


def parse_arrival_time(record):
    if "13:00:" not in record:
        raise Exception("Check the timestamp: " + record)

    # timestamp format: 13:00:00.642598
    start = record.find("13:00:") + len("13:00:")
    end = record.find(" IP")

    sec = int(record[start:start+2])
    micro_sec = int(record[start+3:start+9])

    total = sec * 1000000 + micro_sec

    return total


def main():
    input_file = "./packet-trace.txt"

    all_records = read_input(input_file)

    # packets with size information
    icmp = get_records(all_records, "icmp ")    # 5439
    udp = get_records(all_records, "UDP")       # 1614
    tcp = get_records(all_records, "win")       # 182518
    others = get_other_records(all_records)     # 10429
    print("Number of packets with size info: ICMP = {}; UDP = {}; TCP = {}"
          .format(len(icmp), len(udp), len(tcp)))

    if len(icmp + udp + tcp + others) != len(all_records):
        raise Exception("Sum of packets number doesn't match total number of records!")

    # packets with incomplete info.
    icmp_others = get_records(others, "icmp")   # 10
    udp_others = get_records(others, "udp")     # 106
    tcp_others = get_records(others, "tcp")     # 56

    print("Number of packets with incomplete info: ICMP = {}; UDP = {}; TCP = {}"
          .format(len(icmp_others), len(udp_others), len(tcp_others)))

    print("Number of packets total: ICMP = {}; UDP = {}; TCP = {}"
          .format(len(icmp + icmp_others), len(udp + udp_others), len(tcp + tcp_others)))

    # write to files:
    # write_to_file(icmp, "icmp_packets.txt")
    # write_to_file(udp, "udp_packets.txt")
    # write_to_file(tcp, "tcp_packets.txt")
    # write_to_file(others, "other_packets.txt")

    size_i = process_icmp(icmp)
    size_u = process_upd(udp)
    size_t = process_tcp(tcp)

    sizes = size_i + size_u + size_t

    avg_p_size = sum(sizes)/len(sizes)

    print("Average packet size (ICMP, UDP, TCP) = {} bytes, Total no. of packets = {}".format(avg_p_size, len(sizes)))

    find_top_x_common_p_size(5, sizes)  # top 5 common packet sizes

    justify_poisson_arrival(all_records)


if __name__ == "__main__":
    main()
