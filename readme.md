# pg_tcpcheck 🐘🛡️

**pg_tcpcheck** es una funcion de diagnóstico de red diseñada para ejecutarse directamente desde PostgreSQL. Permite verificar la disponibilidad de servicios TCP (puertos) en servidores remotos de forma masiva, segura y eficiente.

---

## 🚀 Características Principales

* **Escaneo Masivo:** Soporta múltiples objetivos en una sola cadena (ej. `'10.0.0.1, 192.168.1.50:8080'`).
* **Seguridad Blindada:** * **Validación INET:** Protección nativa contra inyección de comandos shell.
* **Search Path Hardening:** Previene ataques de secuestro de esquemas.
* **Privilegios Controlados:** Ejecución vía `SECURITY DEFINER` con acceso restringido.


* **Verbocidad Dinámica:** Controla el nivel de logs (`NOTICE`, `DEBUG`, `ERROR`) mediante parámetros.
* **Sintaxis Flexible:** Compatible con notación por nombre de PostgreSQL (el orden de los parámetros no importa).

---

## 🛠️ Instalación

> [!IMPORTANT]
> Esta función requiere privilegios de **Superusuario** para su creación, ya que utiliza el comando `COPY FROM PROGRAM` o que el usuario que cree la funcion tenga el permiso pg_execute_server_program.

1. Por seguridad, la función nace sin permisos para el público. Otorga acceso solo a los roles necesarios:

```sql
GRANT EXECUTE ON FUNCTION systools.pg_tcpcheck TO tu_usuario_admin;

```

---

## 💡 Ejemplos de Uso

Al ser una **SRF (Set Returning Function)**, se consulta como si fuera una tabla:

### 1. Verificación simple (un solo puerto)

```sql
SELECT * FROM systools.pg_tcpcheck('10.0.0.1, 10.0.0.2', 5432);

```

### 2. Formato Mixto (IPs y Puertos específicos)

```sql
SELECT * FROM systools.pg_tcpcheck('10.0.0.1:5432, 10.0.0.2:80, 8.8.8.8');

```

### 3. Usando parámetros por nombre (Sin importar el orden)

```sql
SELECT * FROM systools.pg_tcpcheck(
    p_log_level => 'error',      -- No muestra advertencias de IPs mal escritas
    p_timeout   => 5,            -- Espera 5 segundos
    p_targets   => '1.1.1.1, 8.8.8.8:53'
);

```

---

## 📊 Salida de la Función

La función devuelve una tabla con la siguiente estructura:

| Columna | Tipo | Descripción |
| --- | --- | --- |
| `ip_server` | `INET` | La dirección IP procesada y validada. |
| `port` | `INTEGER` | El puerto que se intentó contactar. |
| `status_connect` | `BOOLEAN` | `TRUE` si hubo respuesta, `FALSE` si falló. |

---

## ⚠️ Requisitos de Sistema

* **PostgreSQL:** Versión 9.3 o superior (recomendado 9.5+ para mejor soporte de parámetros por nombre).
* **OS:** Servidor basado en Linux/Unix con `bash` y el comando `timeout` instalados.
* **Permisos:** El usuario que crea la función debe tener acceso a `COPY PROGRAM`.

 
