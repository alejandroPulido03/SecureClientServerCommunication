# SecureClientServerCommunication

This project was developed for the computational infrastructure class. The project simulate the communication between a server and several clients, using sockets to simulate the communication and a provided secure communication protocol

### Execution

To run the program, first it must be compiled on the correct Java version with the following command (from the project root folder):

```sh
javac -d bin ./src/*
```

Then, to run the program, there are 3 execution modes:

1. Server mode:

```sh
    java -cp bin Channel server <PORT>
```

2. Client mode:

```sh
    java -cp bin Channel client <IP> <PORT> <NUMBER OF CLIENTS>
```

3. Client and server mode:

```sh
    java -cp bin Channel both <IP> <PORT> <NUMBER OF CLIENTS>
```

### Considerations

- Java 11 compatible with openjdk version "11.0.18".
- The server can only listen to loopback IP addresses (127.0.0.1 to 127.255.255.255), so it must be executed with one of these IP addresses.
- The server creates delegates as clients connect, so it is not necessary to declare the number of delegates.
- The server listens indefinitely, so multiple clients can be executed in various terminals.
