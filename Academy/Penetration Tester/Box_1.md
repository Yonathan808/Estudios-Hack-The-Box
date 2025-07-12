Lo primero que se hace es agregar la IP y dominio al "**/etc/hosts**" para que carguen bien todos los recursos de la pagina

<img width="1418" height="373" alt="image" src="https://github.com/user-attachments/assets/ab4023e1-06bb-47ee-9b5e-1dbb3cb146f6" />

Luego se hace una enumeración basica, yo uso "_dirsearch_" ya que trae una buena wordlist precargada
```dirsearch -u "URL"```

<img width="601" height="637" alt="image" src="https://github.com/user-attachments/assets/3a545f80-635e-4200-a682-bb2d634e4784" />

Primero probe entrando a "_/admin/index.php_" donde hay una interfaz para ingresar las credenciales. En este probe manualmente credenciales "**admin:admin**" y funcionaron

<img width="1307" height="587" alt="image" src="https://github.com/user-attachments/assets/c6618691-4e79-49bb-9812-73f4a9786f4e" />



