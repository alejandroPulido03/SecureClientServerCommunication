# Caso 3 Infraestructura computacional

## Integrantes

-   Gabriela García Suarez – 202210869
-   François Morales Segura – 202211168
-   Alejandro Pulido Bonilla – 202215711

### Ejecución

Para ejecutar el programa, primero se debe compilar sobre la versión de Java correcta con el siguiente comando (Sobre la carpeta raíz del proyecto):

```sh
javac -d bin ./src/*
```

Luego, para ejecutar el programa, hay 3 modos de ejecución:

1. Modo servidor:

```sh
    java -cp bin Channel server <PUERTO>
```

2. Modo cliente:

```sh
    java -cp bin Channel client <IP> <PUERTO> <NUMERO DE CLIENTES>
```

3. Modo cliente y servidor:

```sh
    java -cp bin Channel both <IP> <PUERTO> <NUMERO DE CLIENTES>
```

### Consideraciones

-   La carpeta `bin` contiene los archivos compilados en Java 11 con el openjdk version "11.0.18"
-   El servidor solo puede escuchar de direcciones IP del loopback (127.0.0.1 a 127.255.255.255) por lo que se debe ejecutar con alguna de estas direcciones IP
-   El servidor crea delegados conforme se conectan clientes, por lo que no es necesario declarar el número de delegados
-   El servidor escucha indefinidamente, por lo que se pueden ejecutar múltiples clientes en varios terminales
