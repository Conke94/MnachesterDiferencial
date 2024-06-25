import plotly.graph_objects as go
from tkinter import ttk
import tkinter as tk
import socket

def generateGraph(bits):
    encoded_signal = differential_manchester_encoding(bits)

    x = list(range(len(encoded_signal)))
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=x,
        y=encoded_signal,
        mode='lines+markers',
        line=dict(shape='hv'),
        name='Manchester Differential'
    ))

    fig.update_layout(
        title='Gráfico de Codificação Manchester Diferencial',
        xaxis_title='Tempo',
        yaxis_title='Nível de Sinal',
        yaxis=dict(
            tickvals=[0, 1],
            ticktext=['Low (0)', 'High (1)'],
            autorange='reversed' 
        )
    )

    fig.show()

def differential_manchester_encoding(bits):
    encoded_signal = []
    current_level = '1'

    for bit in bits:
        if bit == '1':
            if current_level == '0':
                encoded_signal.append('0')
                encoded_signal.append('1')
                current_level = '1'
            else:
                encoded_signal.append('1')
                encoded_signal.append('0')   
                current_level = '0'
        elif bit == '0':
            if current_level == '0':
                encoded_signal.append('1')
                encoded_signal.append('0')
                current_level = '0'
            else:
                encoded_signal.append('0')
                encoded_signal.append('1')
                current_level = '1'
    
    return encoded_signal

def string_to_bits(str):
    string_in_bits = []
    for letter in str:
        ascii_value = ord(letter)
        binary_value = bin(ascii_value)[2:]
        binary_value.zfill(8)
        for bit in binary_value:
            string_in_bits.append(bit)
    return string_in_bits

#Caeser Cipher
def encrypt(str_inserted):
    message = str_inserted
    key = 1
    characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    encrypted_value = ''
    message = message.upper()
    for character in message:
        if character in characters:
            num = characters.find(character)
            num = num + key
            if num >= len(characters):
                num = num - len(characters)
            elif num < 0:
                num = num + len(characters)
            encrypted_value = encrypted_value + characters[num]
        else:
            encrypted_value = encrypted_value + character
    return encrypted_value

def enterPressed(event):
    str_inserted = entry.get()
    encrypted_value = encrypt(str_inserted)
    binary_value = string_to_bits(encrypted_value)
    result_label.config(text=f"Mensagem escrita: {str_inserted}\nMensagem encriptada: {encrypted_value}\nMensagem em binário: {binary_value}")
    generateGraph(binary_value)
    sendMessage(differential_manchester_encoding(binary_value), 'localhost')

def sendMessage(message, host, port=1234):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    try:
        binary_string = ''.join(message)  # Converte a lista de bits em uma string
        message_bytes = binary_string.encode('utf-8')  # Converte a string em bytes
        client_socket.sendall(message_bytes)
        print(f'Mensagem enviada: {message_bytes}')
    finally:
        client_socket.close()

window = tk.Tk()
entry_label = ttk.Label(window, text = "Digite a mensagem: ")
entry_label.pack()
entry = ttk.Entry(window, width=40)
entry.pack()
entry.bind('<Return>', enterPressed)
result_label = ttk.Label(window, text="")
result_label.pack(pady=10)
window.mainloop()