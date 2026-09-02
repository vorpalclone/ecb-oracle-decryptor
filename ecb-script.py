from Crypto.Cipher import AES
from bs4 import BeautifulSoup
import binascii
import requests
import string

chartlist = string.printable

URL = "http://URL"

BLOCK_SIZE = 0


def chat_to_oracle(username):
    r = requests.post(URL, data = {'username' : username})
    #Parse the response
    soup = BeautifulSoup(r.text, 'html.parser')
    #Find the encrypted text
    value = str(soup.find(id='encrypted-result').find('strong'))
    #Extract the value
    value = value.replace('<strong>', '').replace('</strong>', '')

    return value

### Calculate Block Size ###

def calculate_block_size():
    #To calculate the block size, we need to keep sending a large username value until the ciphertext length grows twice

    #Get the initial ciphertext length
    username = "A"
    original_length = len(chat_to_oracle(username))

    #Now grow the username until the length becomes larger, keeping count
    first_change_len = 1
    while (len(chat_to_oracle(username)) == original_length):
        username += "A"
        first_change_len += 1

    print ("First growth was at position: " + str(first_change_len))

    #Get the new length
    new_length = len(chat_to_oracle(username))

    #Now grow the username a second time
    second_change_len = first_change_len
    while (len(chat_to_oracle(username)) == new_length):
         username += "A"
         second_change_len += 1

    print ("Second growth was at position: " + str(second_change_len))

    #With these two values, we can now determine the block size:
    BLOCK_SIZE = second_change_len - first_change_len

    print ("BLOCK_SIZE is: " + str(BLOCK_SIZE))

    return BLOCK_SIZE

def split_ciphertext(ciphertext, block_size):
    #This helper function will take the ciphertext and split it into blocks of the known block size
    #Times two since we have two hex for each char
    block_size = block_size * 2
    chunks = [ ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size) ]
    return chunks

### Calculate the Offset ###

def calculate_offset(block_size):
    #To calculate the offset, we will send known text for double the block size and then gradually grow the text until we get two blocks that are the same

    #Create the initial double block size buffer
    initial_text = ""
    for x in range(block_size * 2):
        initial_text += "A"

    #Send this buffer to get the initial ciphertext
    ciphertext = chat_to_oracle(initial_text)

    chunks = split_ciphertext(ciphertext, block_size)

    #Ensure that there are no duplicates already, since this would indicate that there is no offet

    if (len(chunks) != len(set(chunks))):
        print ("No offset found!")
        offset = 0
        return offset

    #If we got here, there is an offet. We will slowly add more text to the start of the username until we get a duplicate
    offset = 0
    while (len(chunks) == len(set(chunks))):
        offset += 1
        #Increment the text by one
        initial_text = "B" + initial_text

        ciphertext = chat_to_oracle(initial_text)
        chunks = split_ciphertext(ciphertext, block_size)

    #Once we exit the loop, it means we have a duplicate chunk and have determined the offset

    print ("Offset is: " + str(offset))

    return offset

### Extract information from the Oracle ###
def brute_forcer(reference_chunk, initial_text, block_size, offset):
    #Character list can be adapted if we expect other characters as well. We could have done the full 0x00 - 0xFF range, but will stay with ASCII for this attack
    charlist = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ'

    actual_char = ''
    found = False

    for char in charlist:
        print ('Testing character: ' + str(char))
        test_text = initial_text + char

        ciphertext = chat_to_oracle(test_text)
        chunks = split_ciphertext(ciphertext, block_size)

        #Test to see if our chunk matches the reference chunk
        if (reference_chunk == chunks[1]):
            print ("Found the char: " + char)
            actual_char = char
            found = True
            break

    if found:
        return char
    else:
        return None

        initial_text += "A"

def extract_full_plaintext(block_size, offset):
    recovered_plaintext = ""
    # Mətnin maksimum uzunluğunu müəyyən edirik (məsələn, 64 bayt və ya ehtiyaca görə)
    max_length = 64  

    for i in range(max_length):
        # Cari blok üçün tələb olunan doldurma (padding) uzunluğu
        padding_len = (block_size - 1 - (len(recovered_plaintext) % block_size))
        
        # Orakula göndəriləcək referans mətni hazırlayırıq
        pad = "B" * offset + "A" * padding_len
        
        # Referans şifrəli mətni alırıq
        ciphertext = chat_to_oracle(pad)
        chunks = split_ciphertext(ciphertext, block_size)
        
        # Hədəf blokun indeksini hesablayırıq
        target_block_index = 1 + (len(recovered_plaintext) // block_size)
        reference_chunk = chunks[target_block_index]

        found_char = False
        
        # Mümkün simvollar üzrə bruteforce
        for char in string.printable:
            # Sınaq mətni: Offset + Doldurma + Artıq tapılmış mətn + Sınaq simvolu
            test_text = "B" * offset + "A" * padding_len + recovered_plaintext + char
            
            test_ciphertext = chat_to_oracle(test_text)
            test_chunks = split_ciphertext(test_ciphertext, block_size)
            
            # Sınaq bloku referans blokla üst-üstə düşürsə, simvol tapılmışdır
            if test_chunks[target_block_index] == reference_chunk:
                recovered_plaintext += char
                print(f"[+] Tapılan mətn: {recovered_plaintext}")
                found_char = True
                break
        
        # Əgər heç bir simvol uyğun gəlməzsə və ya mətn bitibsə (dövrü saxlayırıq)
        if not found_char:
            print("[!] Mətnin sonuna çatıldı və ya simvol tapılmadı.")
            break

    return recovered_plaintext

if __name__ == '__main__':

    #Send a message to the oracle and print the ciphertest
    print ("Testing the oracle")
    ciphertext = chat_to_oracle("SuperUser")
    
    #Calculate the block size from the oracle
    print ("Calculating the block size")
    size = calculate_block_size()
    
    #Calculate the offset from the oracle
    print ("Calculating the offset")
    offset = calculate_offset(size)
    
    print("\n--- Starting Full Plaintext Extraction ---")
    full_text = extract_full_plaintext(size, offset)
    
    print(f"\n[FINAL RESULT] Plaintext: {full_text}")








