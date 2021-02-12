import os
import platform

if platform.system() == "Linux":
    os.system("python src/linux-sniffer.py")
elif platform.system() == "Windows":
    os.system("python src/packet-sniffer.py")
