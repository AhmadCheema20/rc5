from kivy.app import App
from kivy.uix.boxlayout import BoxLayout
from kivy.uix.label import Label
from kivy.uix.textinput import TextInput
from kivy.uix.button import Button
from struct import pack, unpack

def left_rotate(x, s):
    x &= 0xFFFFFFFF
    s %= 32  # Ensure s is non-negative
    return ((x<<s) | (x>>(32-s))) & 0xFFFFFFFF

def right_rotate(x, s):
    x &= 0xFFFFFFFF
    s %= 32  # Ensure s is non-negative
    return (x>>s) | (x<<(32-s)) & 0xFFFFFFFF

def setup_key(secret_key):
    # Convert the secret key to a list of integers
    L = [int.from_bytes(secret_key[i:i+4], 'big') for i in range(0, len(secret_key), 4)]
    
    # Initialize the S array
    S = [(0xB7E15163 + i*0x9E3779B9) & 0xFFFFFFFF for i in range(26)]
    
    # Mix the secret key into the S array
    i = j = 0
    A = B = 0
    for k in range(78):
        A = S[i] = left_rotate((S[i] + A + B) & 0xFFFFFFFF, 3)
        B = L[j] = left_rotate((L[j] + A + B) & 0xFFFFFFFF, (A + B) & 31)
        i = (i + 1) % 26
        j = (j + 1) % len(L)
    
    return S

def encrypt_block(key, plaintext):
    A, B = unpack('>2L', plaintext)
    S = key
    A = (A + S[0]) & 0xFFFFFFFF
    B = (B + S[1]) & 0xFFFFFFFF
    for i in range(1, 13, 2):
        A = left_rotate((A ^ B), B % 32) + S[i]  # Use B % 32 as the shift count
        B = left_rotate((A ^ B), A % 32) + S[i+1]  # Use A % 32 as the shift count
    return pack('>2L', A % 4294967296, B % 4294967296)  # Ensure A and B are within the valid range

def decrypt_block(key, ciphertext):
    A, B = unpack('>2L', ciphertext)
    S = key
    for i in range(12, 0, -2):
        B = right_rotate((B - S[i+1]), A % 32) ^ A  # Use A % 32 as the shift count
        A = right_rotate((A - S[i]), B % 32) ^ B  # Use B % 32 as the shift count
    B = (B - S[1]) & 0xFFFFFFFF
    A = (A - S[0]) & 0xFFFFFFFF
    return pack('>2L', A % 4294967296, B % 4294967296)  # Ensure A and B are within the valid range

class RC5App(App):
    def build(self):
        layout = BoxLayout(orientation='vertical')
        self.key_input = TextInput(hint_text='Enter key in hex')
        self.plaintext_input = TextInput(hint_text='Enter plaintext in hex')
        self.ciphertext_input = TextInput(hint_text='Enter ciphertext in hex')  # New input field for ciphertext
        self.ciphertext_output = Label()
        self.decrypted_output = Label()
        layout.add_widget(self.key_input)
        layout.add_widget(self.plaintext_input)
        layout.add_widget(Button(text='Encrypt', on_press=self.encrypt))
        layout.add_widget(self.ciphertext_output)
        layout.add_widget(self.ciphertext_input)  # Add the new input field to the layout
        layout.add_widget(Button(text='Decrypt', on_press=self.decrypt))
        layout.add_widget(self.decrypted_output)
        return layout

    def encrypt(self, instance):
        key = bytes.fromhex(self.key_input.text)
        plaintext = bytes.fromhex(self.plaintext_input.text)
        key = setup_key(key)
        ciphertext = encrypt_block(key, plaintext)
        self.ciphertext_output.text = 'Ciphertext: ' + ciphertext.hex()

    def decrypt(self, instance):
        key = bytes.fromhex(self.key_input.text)
        ciphertext = bytes.fromhex(self.ciphertext_input.text)  # Use the ciphertext provided by the user
        key = setup_key(key)
        decrypted = decrypt_block(key, ciphertext)
        self.decrypted_output.text = 'Decrypted: ' + decrypted.hex()

if __name__ == '__main__':
    RC5App().run()