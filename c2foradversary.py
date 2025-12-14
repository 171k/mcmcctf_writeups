from Crypto.Cipher import DES3
import struct

# =============================================================================
# MALWARE DECRYPTION SCRIPT - FORENSIC RECONSTRUCTION
# Based on analysis of 'vcruntime140.dll'
# =============================================================================

# --- 1. THE KEYS (Recovered from Stack Strings) ---
# Analysis of function: FUN_25d7f22d1
# The malware builds the key byte-by-byte on the stack in Little Endian.
# We reconstructed the original 8-byte keys from the immediate hex values:
# Key 1 Source: 0xEFCDAB8967452301 -> Reversed: 01 23 45 67 89 AB CD EF
# Key 2 Source: 0x1032547698BADCFE -> Reversed: FE DC BA 98 76 54 32 10
# Key 3 Source: 0x67452301EFCDAB89 -> Reversed: 89 AB CD EF 01 23 45 67

k1 = bytes.fromhex("0123456789ABCDEF")
k2 = bytes.fromhex("FEDCBA9876543210")
k3 = bytes.fromhex("89ABCDEF01234567")

# 3DES uses a 24-byte key (Three 8-byte keys concatenated)
FULL_KEY = k1 + k2 + k3

# --- 2. THE INITIALIZATION VECTOR (IV) ---
# Analysis: The address &DAT_25d7f5018 was passed to CryptSetKeyParam
# Value found in .data section:
IV = bytes.fromhex("1234567890ABCDEF")

# --- 3. THE ENCRYPTED PAYLOAD ---
# Analysis: The address &DAT_25d7f5020 was passed to the decryption routine.
# Size: 0x270 (624 bytes).
# Content: Extracted from .data section.
hex_payload = (
    "9A37F05AF351B3A9AA90ACFE76597C165DBAB9557853ADD6AE37C9250087F339"
    "EF4AA492B39456D2ECF5EDE7A04AC7C1864C2D30B7E7EFBD50D9632429402E54"
    "C1CBF807C8349078F3672EA7F875FD1CCECB0C6218F84A604FAF2B9AED450204"
    "83635A2FE524CC96042D8D046E2AD63CA7474F8848313D790BDCBBCF7EA7FF1C"
    "4EFD54204289DBA252BD1D2A12BC55B6E4938C39535A8FDCD85CB6D6F17196B0"
    "0B792CC06DAD3D71F0C186BF152EAC7AC78CCCBACA3548782F280A87DF6DCDE4"
    "5AB348A8FEB6C6F8FD353A3A6DC7BD97CD2883AEB081AAD4E1D72A8D4CAF2CF1"
    "2F665570F242BA55C64C38F3E66322D5680AEE0EA676D5A1CFDECC27BA033D29"
    "269DB6F2F37CE3B3FE62B0D6A0EED31CB9203FB612F4D7C4319D5ECB47AE6D98"
    "23EBE39AED33D77E483E105C0C7AFEBE00740C2F9AA9CB3B708D25E15147EFA7"
    "3905D6349346BFAD63B7D03A248C0CD9C9A7B4C01CBF799A19BF105964B00AE5"
    "977CB8BD77184A7C032FCEBE631B34DC57ABF6C3570904493BC5179294CCFDE4"
    "0D7E99E1FF58BB3718A5046E6D16756FB12D64A120497519FC16EF0065CB108D"
    "8B258AE1F59ECB2260F3BFD1460FC7470E60FDE6F66AF84B29D88718521C498C"
    "A7EBE3BCDB4DEA41D744B9A4E96BC4A29D15853384AAF3252C9E4E8F78C3A79F"
    "E45065D211123F75249081034B9B6F099EB881114CC3DC399A84C31E94F1F2F2"
    "6A4CA7F17B21A1266FDE0205DA3AAEE3F21F9C2EC75DE6010085604853AB8A94"
    "A8218212D2A12196E29D2D6072728BD94647E96A774E41B12C58B888CAAE9DCC"
    "5F36D406C6CB13153079DA4B71D9806AB7F55A2469BAFD95DF8761FF0C36BD0C"
    "2D991DCB95472981D2252543086FECC37002000000000000"
)

CIPHERTEXT = bytes.fromhex(hex_payload)

def run_decryption():
    print(f"[*] Starting 3DES Decryption...")
    print(f"[*] Key: {FULL_KEY.hex().upper()}")
    print(f"[*] IV:  {IV.hex().upper()}")
    print(f"[*] Payload Size: {len(CIPHERTEXT)} bytes")
    
    try:
        # Initialize 3DES Cipher in CBC Mode
        cipher = DES3.new(FULL_KEY, DES3.MODE_CBC, IV)
        
        # Perform Decryption
        decrypted_data = cipher.decrypt(CIPHERTEXT)
        
        print("\n[+] Decryption Successful!")
        print("-" * 50)
        
        # The payload contains shellcode mixed with strings. 
        # We will attempt to filter for readable ASCII strings to find the C2.
        readable_strings = []
        current_string = ""
        
        for byte in decrypted_data:
            char = chr(byte)
            # Check for printable ASCII (A-Z, a-z, 0-9, punctuation)
            if 32 <= byte <= 126: 
                current_string += char
            else:
                if len(current_string) > 4: # Filter noise
                    readable_strings.append(current_string)
                current_string = ""
        
        # Print all found strings
        print("Found Strings in Payload:")
        for s in readable_strings:
            print(f" > {s}")
            
        print("-" * 50)
        
    except Exception as e:
        print(f"[!] Error: {e}")

if __name__ == "__main__":
    run_decryption()
