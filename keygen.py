import hashlib


lookup_str = "agnahaakeaksalmaltalvandanearmaskaspattbagbakbiebilbitblablebliblyboabodbokbolbomborbrabrobrubudbuedaldamdegderdetdindisdraduedukdundypeggeieeikelgelvemueneengennertesseteettfeifemfilfinfloflyforfotfrafrifusfyrgengirglagregrogrygulhaihamhanhavheihelherhithivhoshovhuehukhunhushvaideildileinnionisejagjegjetjodjusjuvkaikamkankarkleklikloknaknekokkorkrokrykulkunkurladlaglamlavletlimlinlivlomloslovluelunlurlutlydlynlyrlysmaimalmatmedmegmelmenmermilminmotmurmyemykmyrnamnednesnoknyenysoboobsoddodeoppordormoseospossostovnpaiparpekpenpepperpippopradrakramrarrasremrenrevrikrimrirrisrivromroprorrosrovrursagsaksalsausegseiselsensessilsinsivsjusjyskiskoskysmisnesnusolsomsotspastistosumsussydsylsynsyvtaktaltamtautidtietiltjatogtomtretuetunturukeullulvungurourtutevarvedvegveivelvevvidvikvisvriyreyte"


def byte_to_hex(byte: int) -> str:
    return hex(byte)[2:]

def string_to_hex(string: str) -> str:
    str_bytes = str.encode(string)

    hex_str = ''

    for byte in str_bytes:
        hex_str += byte_to_hex(byte)

    return hex_str

def generate_key(MAC: str, mode: int, passphrase_length_param: int) -> str:
    passphrase_length = 0;

    if mode == 0:
        passphrase_length = 26
    elif mode == 1:
        passphrase_length = 10
    elif mode == 2:
        passphrase_length = 20 if not passphrase_length_param else passphrase_length_param
    elif mode == 3:
        passphrase_length = 16
    else:
        passphrase_length = 10

    MAC_MD5_bytes = hashlib.md5(MAC.encode()).digest()

    MAC_MD5_str = ''
    char_sum = 0

    for byte in MAC_MD5_bytes:
        byte_hex = byte_to_hex(byte)

        if len(byte_hex) == 1:
            byte_hex = byte_hex + byte_hex

        byte_hex = byte_hex.upper()

        MAC_MD5_str +=  byte_hex
        char_sum += ord(byte_hex[0]) + ord(byte_hex[1])


    lookup_int = char_sum % 265;
    lookup_characters = string_to_hex(lookup_str[(lookup_int * 3):(lookup_int * 3 + 3)])

    # Even
    if char_sum % 2 == 0:
        lookup_characters = lookup_characters.upper()


    assembled_string = f'{MAC_MD5_str[0]}{lookup_characters[0]}{lookup_characters[1]}{MAC_MD5_str[1]}{MAC_MD5_str[2]}{lookup_characters[2]}{lookup_characters[3]}{MAC_MD5_str[3]}{MAC_MD5_str[4]}{MAC_MD5_str[5]}{lookup_characters[4]}{lookup_characters[5]}{MAC_MD5_str[6:]}'

    passphrase_bytes = hashlib.md5(assembled_string.encode()).digest()

    passphrase = ''

    for byte in passphrase_bytes:
        byte_hex = byte_to_hex(byte)

        if len(byte_hex) == 1:
            byte_hex = byte_hex + byte_hex

        byte_hex = byte_hex.upper()

        passphrase +=  byte_hex

    if mode == 0:
        return passphrase[0:passphrase_length]
    elif mode == 1:
        return passphrase[31:21:-1]
    elif mode == 2:
        return passphrase[26-passphrase_length:26]
    elif mode == 3:
        return passphrase[16:0:-1]
    else:
        return passphrase[32:21:-1]


def valid_mac_address(mac: str) -> bool:
    # Remove ":" if present
    mac = mac.replace(':', '')

    # Mac should be exactly 12 characters
    if len(mac) != 12:
        return False

    # Only allow hex characters
    allowed_chars = '1234567890abcdef'

    return all(char in allowed_chars for char in mac)



if __name__ == '__main__':
    # Ask for MAC Address
    while True:
        mac_input = input('Enter the VDSL MAC Address> ').lower()

        if not valid_mac_address(mac_input):
            print('Please enter a valid MAC')
            print()
        else:
            break


    # Ask for mode
    while True:
        mode_input = input('Enter mode> ')

        if not mode_input.isdigit():
            print('Please enter a valid mode')
            print()
        else:
            break


    # Ask for key length
    while True:
        length_input = input('Enter key length> ')

        if not length_input.isdigit():
            print('Please enter a valid key length')
            print()
        else:
            break


    print()
    print(f'The key is: {generate_key(mac_input, int(mode_input), int(length_input))}')






