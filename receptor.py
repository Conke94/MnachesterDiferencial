# -*- coding: utf-8 -*-
import socket
import plotly.graph_objects as go
from tkinter import ttk
import tkinter as tk
import socket

def controller():
    encoded_signal = receiveMessage('localhost', 1234)
    generateGraph(encoded_signal)
    original_signal = diferentialManchesterDecoding(encoded_signal)
    encrypted_text = binaryToString(original_signal)
    original_text = decrypt(encrypted_text)
    # showOnScreen(text)

def receiveMessage(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(1)
    print(f'Servidor escutando em {host}:{port}')

    while True:
        client_socket, client_address = server_socket.accept()
        try:
            data = client_socket.recv(1024)
        finally:
            client_socket.close()
            return data.decode('utf-8')

def generateGraph(data):
    graph_data = []
    for bit in data:
        graph_data.append(bit)

    x = list(range(len(graph_data)))
    fig = go.Figure()

    fig.add_trace(go.Scatter(
        x=x,
        y=graph_data,
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

def diferentialManchesterDecoding(encoded_signal):
    decoded_signal = []
    current_level = encoded_signal[2]

    if(encoded_signal[0] == '1'):
        decoded_signal.append('1')
    else:
        decoded_signal.append('0')

    for i in range(2, len(encoded_signal), 2):
        first_bit = encoded_signal[i]
        second_bit = encoded_signal[i + 1]

        if first_bit == current_level:
            decoded_signal.append('1')
        else:
            decoded_signal.append('0')

        current_level = second_bit

    return decoded_signal

def binaryToString(signal):
    chars = []
    for b in range(0, len(signal), 8):
        byte = signal[b:b+8]
        byte_str = ''.join(byte)
        ascii_value = int(byte_str, 2)
        chars.append(chr(ascii_value))
    return ''.join(chars)

def decrypt(encrypted_message):
    key = 7
    characters = 'AÁÀÃÂaáàãâBbCcçDdEÉÈÊeéèêFfGgHhIÍÌÎiíìîJjKkLlMmNnOÓÒÕÔoóòõôPpQqRrSsTtUÚÙÛuúùûVvWwXxYyZz'
    decrypted_value = ''
    for character in encrypted_message:
        if character in characters:
            num = characters.find(character)
            num = num - key
            if num < 0:
                num = num + len(characters)
            decrypted_value = decrypted_value + characters[num]
        else:
            decrypted_value = decrypted_value + character
    
    return decrypted_value

if __name__ == "__main__":
    controller()