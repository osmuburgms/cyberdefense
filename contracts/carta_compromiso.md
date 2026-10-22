CARTA DE COMPROMISO

En la ciudad de Guayaquil, a los 21 días del mes de Octubre del año 2026, convienen en suscribir la presente Carta de Compromiso la PhD. Margarita Delrocio Filian Gómez, en calidad de directora del Centro de Datos de la Facultad de Ingeniería en Electricidad y Computación (FIEC) de la Escuela Superior Politécnica del Litoral (ESPOL), en adelante "el cliente", y las estudiantes Nicole Fernanda Azú Perlaza y Óscar Tomás Muñoz Burgos, pertenecientes a la carrera de Ingeniería en Telemática, en adelante "los estudiantes", bajo la supervisión del tutor PhD. Washington Adrián Velásquez Vargas.

Las partes declaran que el presente Proyecto Integrador denominado "Ciberdefensa inteligente y adaptativa para la detección de amenazas y mitigación automática en redes programables mediante IA y SDN" forma parte de las actividades académicas de los estudiantes antes mencionados, por lo que su desarrollo se ajustará a la legislación, normativa institucional y disposiciones vigentes aplicables a proyectos académicos, incluyendo la normativa en materia de protección de datos personales, propiedad intelectual y las políticas de seguridad de la ESPOL y del Centro de Datos.

Como punto de contacto del lado del cliente se designa a la PhD. Margarita Delrocio Filian Gómez, en el cargo de directora del Centro de Datos de la FIEC, correo electrónico oficial mfilian@espol.edu.ec, cuya asunción del rol como punto de contacto se acredita mediante el correo electrónico remitido por la propia directora al tutor del proyecto, PhD. Washington Adrián Velásquez Vargas, de fecha [FECHA], que se adjunta como Anexo 1 a la presente carta.


I.	COMPROMISOS DEL CLIENTE

El cliente se compromete a:

·	Tiempo de acceso a instalaciones y recursos: otorgar a los estudiantes acceso al Centro de Datos de la FIEC y a los recursos de red necesarios para el desarrollo del proyecto, en los horarios que defina el Centro de Datos.

·	Despliegue del sistema: disponer un servidor físico o virtual dentro del Centro de Datos, con 2 vCPUs, 16 GB de RAM y 500 GB de almacenamiento, con acceso a segmentos de red o VLAN de pruebas, para instalar y operar el sistema de manera que pueda visualizar, analizar y proteger la red del centro de datos en tiempo real.

·	Software y documentación: sistema operativo Linux (Ubuntu) para el servidor, diagrama y topología de la red del Centro de Datos, credenciales o comunidades de solo lectura (SNMP), manuales de los equipos, accesos a VLANs para pruebas, licencias (si existen).

·	Inventario de equipos: facilitar el inventario de los equipos de cómputo instalados en el Centro de Datos, con los campos mínimos de identificación, dirección IP, dirección MAC, área o departamento, segmento de red, tipo de equipo, sistema operativo, ubicación física y criticidad, y mantenerlo actualizado durante la ejecución del proyecto. El cliente revisará los equipos dados de alta en la plataforma, así como la asignación de un área o departamento responsable para cada equipo, la cual se visualizará en la topología de la plataforma.

·	Canal de notificación: facilitar un canal de notificación para el equipo de soporte de TI, que podrá ser el correo electrónico corporativo (proporcionando los datos de conexión SMTP y la lista de destinatarios autorizados) o una aplicación de mensajería institucional (proporcionando el token, el identificador de canal o el bot correspondiente), así como definir los niveles de severidad y el escalamiento de las notificaciones. El cliente reconoce que el uso de este canal se limita a la notificación de eventos técnicos del proyecto y no sustituye los canales oficiales de reporte de incidentes del Centro de Datos.

·	Política de seguridad: compartir las políticas de filtrado, bloqueos y listas de restricción vigentes en el Centro de Datos (servicios, dominios, puertos y protocolos restringidos, segmentación por áreas), de manera que las reglas que se implementen en la plataforma sean consistentes con la política institucional vigente.

·	Otras colaboraciones: designar un administrador de red disponible para resolver dudas, autorizar por escrito las pruebas solicitadas, aprobar de forma explícita la aplicación de reglas de filtrado sobre la red productiva, brindar retroalimentación en reuniones de seguimiento y facilitar la instalación y posterior retiro del equipo de cómputo.


II.	COMPROMISOS DE LOS ESTUDIANTES

Los estudiantes se comprometen a:

·	Software: aportar todo el software de desarrollo y las herramientas utilizadas (React, FastAPI, Ryu, Open vSwitch, modelos de Machine Learning, contenedores), los cuales son de código abierto o de licencia sin costo, así como el código fuente desarrollado.

·	Módulo de notificaciones: desarrollar e integrar en la plataforma un módulo de notificación hacia el equipo de soporte de TI, a través del canal acordado, que emita avisos ante la detección de un ataque, ante el aislamiento o bloqueo de un equipo y ante la generación de recomendaciones de seguridad. El módulo deberá permitir configurar los destinatarios, el nivel de severidad y el contenido de la notificación, evitando el envío de notificaciones duplicadas o irrelevantes.

·	Inventario y configuración de equipos: desarrollar un módulo de registro de activos que permita dar de alta, editar, consultar, dar de baja y buscar equipos del Centro de Datos, especificando su nombre, dirección IP, dirección MAC, área o departamento, segmento de red, tipo, sistema operativo, ubicación, propietario y criticidad, así como relacionar cada equipo con los eventos de seguridad detectados sobre él. La plataforma deberá permitir configurar los nuevos equipos que se instalen en el Centro de Datos y representarlos en la topología de la red, asociándolos a su área o departamento responsable, de modo que el operador pueda visualizar el estado de la red segmentado por áreas. La plataforma deberá validar los datos ingresados (formato de direcciones, duplicados y consistencia con los segmentos de red declarados) e informar los errores de validación al usuario.

·	Carga masiva de datos de equipos: implementar la importación masiva de equipos mediante archivos de configuración en los formatos JSON, YAML, XML, XLSX y CSV, con un archivo plantilla con los campos y el formato de ejemplo, así como un modo de verificación previa (simulación) que reporte los registros con errores antes de aplicarlos, de modo que la carga pueda ser validada por el cliente antes de su ejecución definitiva.

·	Reglas de tráfico y filtrado: desarrollar un módulo de gestión de reglas de tráfico, similar al de un firewall, que permita definir políticas de filtrado por equipo individual, por grupo o departamento, por segmento de red y por puerto, protocolo o destino (dirección IP, dominio o servicio), con acciones de permitir, bloquear, alertar o limitar, y con prioridad y vigencia configurables. Las reglas se aplicarán sobre la red programable mediante el controlador, y toda regla aplicada sobre tráfico productivo será habilitada únicamente con la autorización previa y por escrito del contacto del cliente, sin modificar las políticas o listas de control de acceso ya instaladas en el Centro de Datos.

·	Recomendaciones post-incidente: implementar en el informe de incidentes y en la notificación enviada al equipo de soporte de TI un conjunto de recomendaciones concretas de mitigación y prevención, derivadas del tipo de ataque detectado y de los servicios expuestos por el equipo afectado, tales como el cierre de puertos o servicios innecesarios, la restricción de acceso administrativo, la corrección de credenciales débiles o la aplicación de parches de seguridad. Las recomendaciones se presentan de forma orientativa y no sustituyen la evaluación técnica del equipo de soporte del cliente.

·	Otras colaboraciones: desarrollar el sistema conforme al alcance acordado, documentar técnica y manualmente lo implementado, brindar capacitación y soporte razonable al cliente, mantener la confidencialidad de la información sensible o de uso interno proporcionada por el cliente durante la ejecución del Proyecto Integrador, actuar con ética profesional y realizar exclusivamente las acciones autorizadas por el cliente.


III.	PRUEBAS Y VALIDACIONES

El cliente autoriza a los estudiantes a realizar pruebas funcionales, de integración, de rendimiento y pruebas controladas de detección y prevención de intrusiones (generación de tráfico sintético y escaneos de red), sujetas a las siguientes condiciones:

·	Las pruebas se realizarán únicamente en los equipos, servidores y segmentos de red expresamente autorizados por el cliente, con un alcance mínimo dentro de la VLAN de pruebas y los servidores de prueba asignados al proyecto.

·	Toda prueba que pueda generar tráfico activo requerirá autorización previa del contacto del cliente y se realizará en la ventana de prueba acordada, procurando no afectar servicios productivos.

·	Las pruebas de las reglas de filtrado se ejecutarán inicialmente sobre un segmento o conjunto de equipos de prueba, y su aplicación sobre equipos productivos requerirá la autorización previa y por escrito del contacto del cliente.

·	Las pruebas del módulo de notificación se realizarán con eventos simulados y con destinatarios de prueba acordados, evitando el envío de notificaciones reales sobre incidentes inexistentes.

·	Las pruebas de la carga masiva de datos de equipos se realizarán con archivos de ejemplo y con una verificación previa, sin alterar el inventario real hasta que el cliente valide el resultado.

·	Los estudiantes se abstendrán de realizar actividades fuera del alcance autorizado y cumplirán con la normativa aplicable en materia de datos personales y seguridad de la información.

·	El cliente podrá revocar o limitar el acceso en cualquier momento si lo considera necesario.

·	El periodo de vigencia de las pruebas será desde la firma de la presente hasta el 8 de enero del 2027.


IV.	ENTREGABLES DEL PROYECTO

Los estudiantes entregarán al cliente:

·	Sistema desplegado y operativo en el servidor cedido dentro del Centro de Datos de la FIEC, capaz de visualizar, analizar y proteger la red en tiempo real.

·	Código fuente completo, con su respectivo repositorio en GitHub.

·	Documentación técnica: arquitectura del sistema, guía de instalación y despliegue, guía de configuración, manual de usuario y de administrador.

·	Módulo de notificaciones al equipo de soporte de TI, configurado con el canal acordado, con su documentación de uso y los parámetros de escalamiento definidos.

·	Módulo de inventario de equipos, con la capacidad de alta, edición, consulta, baja y búsqueda de activos, y con la documentación de los campos utilizados.

·	Importador masivo de equipos, con el soporte de los formatos JSON, YAML, XML, XLSX y CSV, el archivo plantilla de ejemplo y la guía de formato de cada campo.

·	Módulo de gestión de reglas de tráfico y filtrado, con la documentación de los criterios de coincidencia, las acciones disponibles, el orden de prioridad y el procedimiento de activación y desactivación de reglas.

·	Motor de recomendaciones de seguridad post-incidente, con el catálogo de recomendaciones asociadas a cada tipo de evento y su incorporación en el informe de incidentes y en la notificación.

·	Informe técnico y de pruebas con los resultados y métricas obtenidas.

·	Copias de respaldo de las configuraciones y parámetros del sistema.

·	Capacitación y demostración final al cliente de 1 hora.


V.	ACEPTACIÓN

Teniendo en cuenta que el Proyecto Integrador en cuestión forma parte de los estudios académicos de los estudiantes antes mencionados y, por ello, se ajusta a la legislación y normativa vigente válida a tal fin; las partes aceptan íntegramente la presente Carta de Compromiso, firmando en conjunto con el tutor académico.



Nicole Fernanda Azú Perlaza		PhD. Margarita Delrocio Filian Gómez		Óscar Tomás Muñoz Burgos
ESTUDIANTE – TELEMÁTICA		CLIENTE DEL PROYECTO INTEGRADOR		ESTUDIANTE – TELEMÁTICA


ANEXOS

Anexo 1. Correo electrónico de la PhD. Margarita Delrocio Filian Gómez, en calidad de directora del Centro de Datos y punto de contacto del cliente, dirigido al tutor del proyecto, mediante el cual acepta el rol y acredita la coordinación del acceso a los recursos del Centro de Datos (fecha: [FECHA]).
