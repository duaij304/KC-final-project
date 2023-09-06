import pyfiglet
from menu import main_menu

shark_wifi_ascii = r"""
(..       \_    ,  |\  /|
 \       O  \  /|  \ \/ /
  \______    \/ |   \  / 
     vvvv\    \ |   /  |
     \^^^^  ==   \_/   |
      `\_   ===    \.  |
      / /\_   \ /      |
      |/   \_  \|      /
 snd         \________/
"""

codesnail_ascii = pyfiglet.figlet_format("MyShark")

print(codesnail_ascii)
print("Welcome to the MyShark Wireshark Companion!")

if __name__ == "__main__":
    main_menu()
