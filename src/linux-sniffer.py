from Tkinter import *
import Tkinter
import time
import socket
import struct
import binascii

window = Tkinter.Tk()
window.title("Packet Sniffer")
window.geometry("1000x750")

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

i = 0
running = BooleanVar()
running.set(True)
label = StringVar()
label.set("CLICK START TO BEGIN...")


def stop():
    running.set(False)
    label.set("STOPPED")
    window.update_idletasks()


def start():
    global i
    label.set("SNIFFING...")
    if running.get():

        packet = s.recvfrom(65565)
        packet = packet[0]

        eth_header = packet[0:14]

        eh = struct.unpack("!6s6sH", eth_header)

        eth_dest = binascii.hexlify(eh[0])

        eth_src = binascii.hexlify(eh[1])

        eth_type = eh[2]

        eth_output = (
            "Etherenet - "
            + "MAC Dest : "
            + str(eth_dest)
            + " MAC Src : "
            + str(eth_src)
            + " Ethernet Type : "
            + str(eth_type)
        )
        listbox.insert(END, eth_output)

        if eth_type == 0x0800:
            ip_header = packet[14:34]

            iph = struct.unpack("!BBHHHBBH4s4s", ip_header)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF

            iph_length = ihl * 4
            iph_length = iph_length + 14

            ttl = iph[5]

            protocol = iph[6]

            s_addr = socket.inet_ntoa(iph[8])

            d_addr = socket.inet_ntoa(iph[9])

            ip_output = (
                "IP - "
                + "Version : "
                + str(version)
                + " IP Header Length : "
                + str(ihl)
                + " TTL : "
                + str(ttl)
                + " Protocol : "
                + str(protocol)
                + " Source Address : "
                + str(s_addr)
                + " Destination Address : "
                + str(d_addr)
            )
            listbox.insert(END, ip_output)

            if protocol == 6:
                tcp_header = packet[iph_length : iph_length + 20]

                tcph = struct.unpack("!HHLLBBHHH", tcp_header)

                source_port = tcph[0]

                dest_port = tcph[1]

                sequence = tcph[2]

                acknowledgement = tcph[3]

                doff_reserved = tcph[4]

                tcph_length = doff_reserved >> 4

                tcp_output = (
                    "TCP - "
                    + "Source Port : "
                    + str(source_port)
                    + " Dest Port : "
                    + str(dest_port)
                    + " Sequence Number : "
                    + str(sequence)
                    + " Acknowledgement : "
                    + str(acknowledgement)
                    + " TCP header length : "
                    + str(tcph_length)
                )
                listbox.insert(END, tcp_output)

                h_size = iph_length + tcph_length * 4
                data_size = len(packet) - h_size

                data = packet[h_size:]

                if dest_port == 80:
                    http = packet[iph_length + 20 : len(packet)]
                    if http:
                        http1 = " ".join(http.split("\r\n"))
                        listbox.insert(END, "HTTP - " + http1)

            elif protocol == 17:
                udp_header = packet[iph_length : iph_length + 8]

                udph = struct.unpack("!HHHH", udp_header)

                source_port = udph[0]

                dest_port = udph[1]

                length = udph[2]

                checksum = udph[3]

                udp_output = (
                    "UDP - "
                    + "Source Port: "
                    + str(source_port)
                    + " Dest Port : "
                    + str(dest_port)
                    + " Length: "
                    + str(length)
                    + " Checksum : "
                    + str(checksum)
                )
                listbox.insert(END, udp_output)

            elif protocol == 1:
                icmp_header = packet[iph_length : iph_length + 8]

                icmph = struct.unpack("!BBHHH", icmp_header)

                icmp_type = icmph[0]

                icmp_code = icmph[1]

                icmp_checksum = icmph[2]

                icmp_identifier = icmph[3]

                icmp_seqnum = icmph[4]

                icmp_output = (
                    "ICMP - "
                    + "Type: "
                    + str(icmp_type)
                    + " Code: "
                    + str(icmp_code)
                    + " Checksum: "
                    + str(icmp_checksum)
                )
                icmp_output = (
                    icmp_output
                    + "Identifier: "
                    + str(icmp_identifier)
                    + " Sequence Number: "
                    + str(icmp_seqnum)
                )
                listbox.insert(END, icmp_output)

        elif eth_type == 0x0806:
            arp_packet = packet[14:42]

            arp_header = struct.unpack("!HHBBH6s4s6s4s", arp_packet)

            hardware_type = arp_header[0]

            protocol_type = arp_header[1]

            hardware_size = arp_header[2]

            protocol_size = arp_header[3]

            opcode = arp_header[4]

            src_mac = binascii.hexlify(arp_header[5])

            src_ip = socket.inet_ntoa(arp_header[6])

            dest_mac = binascii.hexlify(arp_header[7])

            dest_ip = socket.inet_ntoa(arp_header[8])

            arp_output = (
                "ARP - "
                + "Hardware Type: "
                + str(hardware_type)
                + " Protocol Type: "
                + str(protocol_type)
                + " Hardware Size: "
                + str(hardware_size)
                + " Protocol Size: "
                + str(protocol_size)
                + " Opcode: "
                + str(opcode)
                + " Src MAC: "
                + str(src_mac)
                + " Src IP: "
                + str(src_ip)
                + " Dest MAC: "
                + str(dest_mac)
                + " Dest IP: "
                + str(dest_ip)
            )
            listbox.insert(END, arp_output)
        listbox.insert(
            END,
            "*******************************************************************************************************************",
        )
        listbox.see(END)
        i = i + 1
        window.after(10, start)
    else:
        running.set(False)
        label.set("STOPPED")
    window.update_idletasks()


lbl = Tkinter.Label(window, textvariable=label)
lbl.pack()
startButton = Tkinter.Button(window, text="START", command=start)
stopButton = Tkinter.Button(window, text="STOP", command=stop)
startButton.pack()
stopButton.pack()
yscrollbar = Scrollbar(window)
yscrollbar.pack(side=RIGHT, fill=Y)
xscrollbar = Scrollbar(window, orient=HORIZONTAL)
xscrollbar.pack(side=BOTTOM, fill=X)
listbox = Listbox(window, bd=5, selectmode=DISABLED, relief=SUNKEN)
listbox.pack(fill=BOTH, expand=TRUE)
listbox.config(yscrollcommand=yscrollbar.set)
listbox.config(xscrollcommand=xscrollbar.set)
yscrollbar.config(command=listbox.yview)
xscrollbar.config(command=listbox.xview)
window.mainloop()