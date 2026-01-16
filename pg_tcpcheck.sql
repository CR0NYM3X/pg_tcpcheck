/*
-- =============================================================================
-- HERRAMIENTA: pg_tcpcheck
-- REPOSITORIO: github.com/CR0NYM3X/pg_tcpcheck
-- DESCRIPCIÓN: 
--    Verifica la conectividad TCP (estilo telnet) hacia uno o varios destinos 
--    desde el servidor de base de datos. Permite escanear múltiples IPs y 
--    puertos en una sola ejecución.
--
-- PARÁMETROS:
--    - p_targets (TEXT): Lista de destinos separados por coma. 
--      Formatos: '10.0.0.1' (usa puerto default) o '10.0.0.1:8080' (específico).
--    - p_default_port (INT): Puerto a usar si no se especifica uno en la IP.
--    - p_timeout (INT): Tiempo de espera máximo por conexión en segundos.
--    - p_log_level (TEXT): Nivel de verbosidad (notice, log, error, etc.).
--
-- RETORNA: 
--    TABLE (ip INET, port INT, status_connect BOOLEAN)
--
-- SEGURIDAD (Hardening):
--    1. INET Validation: Previene Inyección de Shell mediante casteo nativo.
--    2. SECURITY DEFINER: Requiere privilegios de Superusuario para ejecutarse, 
--       pero puede ser consumida por usuarios limitados.
--    3. SET search_path: Blindaje contra "Search Path Hijacking".
--    4. RBAC: Acceso restringido; REVOKE ALL FROM PUBLIC aplicado por defecto.
--
-- COMPATIBILIDAD: PostgreSQL 9.3+ (Requiere COPY FROM PROGRAM).
-- =============================================================================
*/


CREATE SCHEMA IF NOT EXISTS systools;
 
-- DROP FUNCTION systools.pg_tcpcheck(TEXT, INTEGER, INTEGER, TEXT);
CREATE OR REPLACE FUNCTION systools.pg_tcpcheck(
    p_targets TEXT,
    p_default_port INTEGER DEFAULT 5432,
    p_timeout INTEGER DEFAULT 2,
    p_log_level TEXT DEFAULT 'notice' -- Nuevo parámetro de control
)
RETURNS TABLE (
    ip INET,
    port INTEGER,
    status_connect BOOLEAN
)
LANGUAGE plpgsql
SET search_path = systools, pg_temp
SECURITY DEFINER
AS $$
DECLARE
    v_target_item TEXT;
    v_raw_host TEXT;
    v_raw_port TEXT;
    v_shell_cmd TEXT;
    v_success INTEGER;
    v_old_log_level TEXT;
BEGIN
    -- 1. Validar nivel de log permitido para evitar errores de configuración
    IF LOWER(p_log_level) NOT IN ('debug5', 'debug4', 'debug3', 'debug2', 'debug1', 'log', 'notice', 'warning', 'error') THEN
        RAISE EXCEPTION 'Nivel de log "%" no válido. Use: debug5..1, log, notice, warning o error.', p_log_level;
    END IF;

    -- 2. Aplicar configuración de log localmente para esta función
    -- El tercer parámetro 'true' hace que el cambio sea local a la transacción
    PERFORM pg_catalog.set_config('client_min_messages', LOWER(p_log_level), true);

    -- 3. Crear tabla temporal (Silenciamos cualquier aviso de creación con 'error')
    PERFORM pg_catalog.set_config('client_min_messages', 'error', true);
    CREATE TEMP TABLE IF NOT EXISTS tmp_tcp_check_result (res INTEGER);
    PERFORM pg_catalog.set_config('client_min_messages', LOWER(p_log_level), true);

    -- 4. Procesar targets
    FOR v_target_item IN 
        SELECT unnest(string_to_array(replace(p_targets, ' ', ''), ','))
    LOOP
        v_raw_host := NULL;
        v_raw_port := NULL;

        IF v_target_item ~ ':' THEN
            v_raw_host := split_part(v_target_item, ':', 1);
            v_raw_port := split_part(v_target_item, ':', 2);
        ELSE
            v_raw_host := v_target_item;
            v_raw_port := p_default_port::TEXT;
        END IF;

        -- Validación de IP/Puerto
        BEGIN
            ip := v_raw_host::INET;
            port := v_raw_port::INTEGER;
        EXCEPTION WHEN OTHERS THEN
            -- Esta noticia se ocultará si p_log_level es 'warning' o 'error'
            RAISE NOTICE 'Formato inválido omitido: %', v_target_item;
            CONTINUE;
        END;

        -- Ejecución de comando
        v_shell_cmd := FORMAT(
            'timeout %s bash -c "echo > /dev/tcp/%s/%s" 2>/dev/null && echo 1 || echo 0',
            p_timeout,
            ip,
            port
        );

        TRUNCATE tmp_tcp_check_result;
        
        BEGIN
            EXECUTE FORMAT('COPY tmp_tcp_check_result FROM PROGRAM %L', v_shell_cmd);
            SELECT res INTO v_success FROM tmp_tcp_check_result;
            status_connect := (v_success = 1);
        EXCEPTION WHEN OTHERS THEN
            status_connect := FALSE;
        END;

        RETURN NEXT;
    END LOOP;

    RETURN;
END;
$$; 

-- HARDENING: Seguridad de accesos
-- Eliminamos cualquier permiso automático para el rol PUBLIC (todos los usuarios)
REVOKE ALL ON FUNCTION systools.pg_tcpcheck(TEXT, INTEGER, INTEGER, TEXT) FROM PUBLIC;

-- Otorgamos permiso solo a roles específicos (ejemplo: administrador de FDW)
-- GRANT EXECUTE ON FUNCTION systools.pg_tcpcheck(TEXT, INTEGER, INTEGER, TEXT) TO tu_usuario;


--- Ejemplo de USO 
-- SELECT * FROM systools.pg_tcpcheck(
--    p_targets   => '10.0.0.1:5432, 10.0.0.2, 10.0.0.3c',
--    p_default_port => 5432,
--    p_timeout   => 2,
--    p_log_level => 'notice'
-- );
 
