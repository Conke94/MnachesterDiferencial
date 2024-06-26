# -*- coding: utf-8 -*-
import plotly.graph_objects as go
from tkinter import ttk
import tkinter as tk
import socket

def controller(event):
    str_inserted = entry.get()
    encrypted_value = encrypt(str_inserted)
    binary_value = stringToBits(encrypted_value)
    encoded_signal = differentialManchesterEncoding(binary_value)
    formatted_message = (  
        f"Mensagem escrita: {str_inserted}\n\n"
        f"Mensagem encriptada: {encrypted_value}\n\n"
        f"Mensagem em binário: {binary_value}\n\n"
        f"String Codificação ManchesterD: {encoded_signal}\n"
    )
    
    result_text.config(state='normal')  
    result_text.delete('1.0', tk.END)  
    result_text.insert(tk.END, formatted_message)
    result_text.config(state='disabled')  

    generateGraph(encoded_signal) 
    sendMessage(encoded_signal, 'localhost')

def encrypt(str_inserted):
    message = str_inserted
    key = 7
    characters = 'AÁÀÃÂaáàãâBbCcçDdEÉÈÊeéèêFfGgHhIÍÌÎiíìîJjKkLlMmNnOÓÒÕÔoóòõôPpQqRrSsTtUÚÙÛuúùûVvWwXxYyZz'
    encrypted_value = ''
    for character in message:
        if character in characters:
            num = characters.find(character)
            num = num + key
            if num >= len(characters):
                num = num - len(characters)
            encrypted_value = encrypted_value + characters[num]
        else:
            encrypted_value = encrypted_value + character
    return encrypted_value

def stringToBits(str):
    string_in_bits = []
    for letter in str:
        ascii_value = ord(letter)
        binary_value = bin(ascii_value)[2:].zfill(8)
        for bit in binary_value:
            string_in_bits.append(bit)
    return string_in_bits

def generateGraph(encoded_signal):
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

def differentialManchesterEncoding(bits):
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

def sendMessage(message, host, port=1234):
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect((host, port))

    try:
        binary_string = ''.join(message)  # Converte a lista de bits em uma string
        message_bytes = binary_string.encode('utf-8')  # Converte a string em bytes
        client_socket.sendall(message_bytes)
    finally:
        client_socket.close()

if __name__ == "__main__":
    window = tk.Tk()
    entry_label = ttk.Label(window, text = "Digite a mensagem: ")
    entry_label.pack()
    entry = ttk.Entry(window, width=40)
    entry.pack()
    entry.bind('<Return>', controller)
    frame = ttk.Frame(window)
    frame.pack(expand=True, fill='both', pady=10)

    scrollbar = ttk.Scrollbar(frame)
    scrollbar.pack(side='right', fill='y')

    result_text = tk.Text(
        frame, 
        wrap='word', 
        font=('Arial', 12, 'bold'), 
        bg='lightyellow', 
        fg='blue', 
        padx=10, 
        pady=10, 
        yscrollcommand=scrollbar.set
    )
    result_text.pack(expand=True, fill='both')
    scrollbar.config(command=result_text.yview)
    result_text.config(state='disabled')
    window.mainloop()