from Tkinter import *
import Tkinter

window = Tkinter.Tk()
window.title("NIC - Packet sniffer")
window.geometry("1000x750")

ip_output = (
    str(i)
    + " IP "
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


tcp_output = (
    str(i)
    + " TCP "
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

udp_output = (
    str(i)
    + " UDP "
    + "Source Port: "
    + str(source_port)
    + " Dest Port : "
    + str(dest_port)
    + " Length: "
    + str(length)
    + " Checksum : "
    + str(checksum)
)

icmp_output = (
    str(i)
    + " ICMP "
    + "Type: "
    + str(icmp_type)
    + " Code: "
    + str(icmp_code)
    + " Checksum: "
    + str(icmp_checksum)
    + " Identifier: "
    + str(icmp_identifier)
    + " Sequence Number: "
    + str(icmp_seqnum)
)

lbl = Tkinter.Label(window, textvariable=label)
lbl.pack()
startButton = Tkinter.Button(window, text="START", command=start)
stopButton = Tkinter.Button(window, text="STOP", command=stop)
startButton.pack()
stopButton.pack()
scrollbar = Scrollbar(window)
scrollbar.pack(side=RIGHT, fill=Y)
listbox = Listbox(window, bd=5, selectmode=BROWSE, relief=SUNKEN)
listbox.pack(fill=BOTH, expand=TRUE)
listbox.config(yscrollcommand=scrollbar.set)
scrollbar.config(command=listbox.yview)

window.mainloop()