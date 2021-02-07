# Network interface controller - protocol analyzer

</br>

## Assignment details

Zhvillimi i aplikacionit qe mundeson pergjimin e kanalit te komunikimit (ose NIC).

</br>

## REQUIREMENTS

***Kali linux***

***Python version > 2.7***

</br>

## Installation

Open the terminal in the source directory and run `packet-sniffer.py`.

This procedure will start a GUI application with 2 buttons. Start and Stop.

By pressing start button, application will start sniffing the active network interface.
A console below the window then shows the content for each packet

</br>

Only by running on the network interface the application will show IP props of that interface:

- Version
- IP header length
- TTL
- Protocol
- Source address
- Destination address

</br>

Based on the protocol number the application will show the various props:

</br>

For protocol number **1** : *ICMP*

- Type
- Code
- Checksum
- Identifier
- Sequence number

</br>

For protocol number **6** : *TCP*

- Source port
- Destination port 
- Sequence number
- Acknowledgement number
- Header length

</br>

For protocol number **17** : *UDP*

- Source port
- Destination port
- Length
- Checksum

## Examples

## Results

## Info
