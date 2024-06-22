import socket
import plotly.graph_objects as go
from tkinter import ttk
import tkinter as tk
import socket

def diferentialManchesterDecoding(encoded_signal):
    decoded_signal = []

    current_level = encoded_signal[0]

    for i in range(0, len(encoded_signal), 2):
        first_bit = encoded_signal[i]
        second_bit = encoded_signal[i + 1]

        if first_bit == current_level:
            decoded_signal.append('1')
        else:
            decoded_signal.append('0')

        current_level = second_bit

    print(decoded_signal)
    return decoded_signal

def generateGraph(data):
    graph_data = []
    for bit in data:
        graph_data.append(bit)
    print(graph_data)

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

def inverseProcess(data):
    generateGraph(data)
    # binary_string = decrypt(data)
    # text = binaryToASCII(binary_string)
    # showOnScreen(text)

def start_server(host='localhost', port=1234):
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
            inverseProcess(data.decode('utf-8'))

if __name__ == "__main__":
    start_server()