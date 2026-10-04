#!/usr/bin/env python3
"""
ampliar_modelos_biblioteca.py — Amplía la biblioteca jurídica local (RAG) con una
colección grande de MODELOS DE DOCUMENTOS (abrev "MEP"): civil, laboral,
administrativo, penal, contratos y extrajudicial.

FIABILIDAD: las plantillas aportan ESTRUCTURA y redacción (secciones, fórmulas,
orden), que es lo que convierte al asistente en experto en producir cada tipo de
documento. Los datos concretos van como [HUECOS] y las citas legales exactas las
pone la propia biblioteca de leyes (CP/CE/LECrim/…) vía RAG + el usuario. NO se
inventan artículos dentro del texto: se usan placeholders o referencias marco
estándar y verificadas en el título.

Idempotente: no duplica modelos ya presentes (clave: articulo). Hace copia de
seguridad antes de escribir.

Uso:  python3 ampliar_modelos_biblioteca.py
"""
import json
import os
import shutil
import sys
from datetime import datetime

INDEX = os.path.expanduser("~/Babel/biblioteca_juridica/index.json")

# (articulo_slug, capitulo, titulo, fuente_ref, texto)
MODELOS = [
    # ─────────────────────────── CIVIL ───────────────────────────
    ("demanda-juicio-ordinario", "Demanda civil",
     "Modelo de demanda de juicio ordinario — estructura conforme a LEC arts. 399 y ss.",
     "Elaboración propia — LEC arts. 399 y ss.",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [PROCURADOR], Procurador/a de los Tribunales, en nombre y representación de "
     "[NOMBRE DEL DEMANDANTE], según acredito mediante [poder / apud acta], bajo la dirección "
     "letrada de D./Dña. [ABOGADO], ante el Juzgado comparezco y, como mejor proceda en Derecho, DIGO:\n\n"
     "Que por medio del presente escrito formulo DEMANDA DE JUICIO ORDINARIO contra "
     "[NOMBRE DEL DEMANDADO], con domicilio en [DIRECCIÓN], en reclamación de [OBJETO/CUANTÍA], "
     "con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- [Relación de hechos, numerada y cronológica].\n"
     "SEGUNDO.- [Documentos en que se funda la pretensión: se acompañan como Documento nº …].\n"
     "TERCERO.- [Cuantía del procedimiento y su forma de cálculo].\n\n"
     "FUNDAMENTOS DE DERECHO\n"
     "I.- COMPETENCIA Y PROCEDIMIENTO. [Juzgado competente y clase de juicio por razón de la cuantía/materia].\n"
     "II.- LEGITIMACIÓN. [Activa y pasiva].\n"
     "III.- FONDO. Al amparo de lo dispuesto en [FUNDAMENTO LEGAL APLICABLE].\n"
     "IV.- COSTAS. [Procedencia conforme a LEC art. 394].\n\n"
     "Por lo expuesto,\n"
     "SUPLICO AL JUZGADO que, teniendo por presentado este escrito con sus documentos, admita la "
     "demanda y, previos los trámites legales, dicte sentencia por la que se [PETICIÓN CONCRETA], "
     "con expresa condena en costas a la parte demandada.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado: El/La Procurador/a y el/la Letrado/a."),

    ("demanda-juicio-verbal", "Demanda civil",
     "Modelo de demanda de juicio verbal — estructura conforme a LEC arts. 437 y ss.",
     "Elaboración propia — LEC arts. 437 y ss.",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [NOMBRE DEL DEMANDANTE], mayor de edad, con DNI [COMPLETAR] y domicilio en [DIRECCIÓN], "
     "[por sí / representado por Procurador y asistido de Letrado si la cuantía lo exige], ante el "
     "Juzgado comparezco y DIGO:\n\n"
     "Que formulo DEMANDA DE JUICIO VERBAL contra [NOMBRE DEL DEMANDADO], domicilio en [DIRECCIÓN], "
     "en reclamación de [OBJETO/CUANTÍA], con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- [Hechos de forma clara y numerada].\n"
     "SEGUNDO.- [Prueba documental acompañada].\n\n"
     "FUNDAMENTOS DE DERECHO\n"
     "I.- COMPETENCIA Y ADECUACIÓN DEL PROCEDIMIENTO (LEC art. 250).\n"
     "II.- FONDO: [FUNDAMENTO LEGAL APLICABLE].\n"
     "III.- COSTAS (LEC art. 394).\n\n"
     "SUPLICO AL JUZGADO que admita la demanda y, tras su tramitación, dicte sentencia estimatoria "
     "por la que se [PETICIÓN CONCRETA], con condena en costas a la demandada.\n"
     "OTROSÍ DIGO que, para el acto de la vista, intereso los medios de prueba de que intento valerme: "
     "[DOCUMENTAL / TESTIFICAL / PERICIAL / INTERROGATORIO].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("contestacion-demanda", "Contestación",
     "Modelo de contestación a la demanda (civil) — estructura conforme a LEC art. 405",
     "Elaboración propia — LEC art. 405",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n"
     "Autos de [Juicio Ordinario / Verbal] nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [NOMBRE DEL DEMANDADO], según consta acreditado en autos, "
     "bajo la dirección letrada de D./Dña. [ABOGADO], ante el Juzgado comparezco y DIGO:\n\n"
     "Que, dentro del plazo conferido, formulo CONTESTACIÓN A LA DEMANDA presentada de contrario, "
     "oponiéndome a la misma con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- [Pronunciamiento sobre CADA hecho de la demanda: se admite / se niega / no consta]. "
     "Se niegan expresamente todos los hechos que no sean reconocidos de forma clara en este escrito.\n"
     "SEGUNDO.- [Versión propia de los hechos y documentos que la sustentan].\n\n"
     "FUNDAMENTOS DE DERECHO\n"
     "I.- EXCEPCIONES [procesales y/o materiales: falta de legitimación, prescripción, caducidad, "
     "litispendencia, cosa juzgada, etc., si procede].\n"
     "II.- FONDO: oposición conforme a [FUNDAMENTO LEGAL APLICABLE].\n"
     "III.- COSTAS a la actora (LEC art. 394).\n\n"
     "SUPLICO AL JUZGADO que, teniendo por contestada la demanda y por opuesta a esta parte, dicte "
     "sentencia por la que se [DESESTIME ÍNTEGRAMENTE LA DEMANDA / se estime la excepción de …], "
     "absolviendo a mi representado, con imposición de costas a la parte actora.\n"
     "OTROSÍ DIGO que propongo los siguientes medios de prueba: [DOCUMENTAL / TESTIFICAL / PERICIAL].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("reconvencion", "Contestación",
     "Modelo de reconvención (en la contestación) — conforme a LEC art. 406",
     "Elaboración propia — LEC art. 406",
     "[Se formula a continuación de la contestación, en el mismo escrito o separadamente según LEC art. 406]\n\n"
     "RECONVENCIÓN\n\n"
     "Que, al amparo del artículo 406 de la LEC, esta parte formula RECONVENCIÓN frente a la actora "
     "[y, en su caso, frente a terceros], con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- [Hechos en que se funda la pretensión reconvencional].\n"
     "SEGUNDO.- [Conexión con el objeto de la demanda principal y documentos].\n\n"
     "FUNDAMENTOS DE DERECHO\n"
     "I.- ADMISIBILIDAD DE LA RECONVENCIÓN (LEC art. 406).\n"
     "II.- FONDO: [FUNDAMENTO LEGAL APLICABLE].\n\n"
     "SUPLICO AL JUZGADO que admita la reconvención y, tras su tramitación conjunta, dicte sentencia "
     "por la que se [PETICIÓN RECONVENCIONAL], con costas a la actora-reconvenida.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-monitorio", "Demanda civil",
     "Modelo de petición inicial de proceso monitorio — conforme a LEC arts. 812 y ss.",
     "Elaboración propia — LEC arts. 812 y ss.",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [ACREEDOR], con DNI/CIF [COMPLETAR] y domicilio en [DIRECCIÓN], ante el Juzgado DIGO:\n\n"
     "Que formulo PETICIÓN INICIAL DE PROCESO MONITORIO frente a [DEUDOR], con domicilio en "
     "[DIRECCIÓN], reclamando una deuda dineraria, vencida y exigible de [IMPORTE EN CIFRA Y LETRA] €, "
     "que acredito mediante los documentos que acompaño (LEC art. 812), con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- Origen de la deuda: [factura / contrato / certificación / albarán…], Documento nº 1.\n"
     "SEGUNDO.- La deuda está vencida y no ha sido satisfecha pese a los requerimientos efectuados.\n\n"
     "FUNDAMENTOS DE DERECHO: LEC arts. 812 y ss.; competencia del domicilio del deudor (LEC art. 813).\n\n"
     "SUPLICO AL JUZGADO que, admitiendo esta petición, requiera al deudor para que, en el plazo legal, "
     "pague la cantidad reclamada o comparezca y se oponga; y de no hacerlo, se despache ejecución.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-desahucio", "Demanda civil",
     "Modelo de demanda de desahucio por falta de pago y reclamación de rentas — LEC arts. 250.1.1 y 440",
     "Elaboración propia — LEC arts. 250.1.1, 437 y 440; LAU",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [ARRENDADOR], bajo dirección letrada de [ABOGADO], DIGO:\n\n"
     "Que formulo DEMANDA DE JUICIO VERBAL DE DESAHUCIO POR FALTA DE PAGO, con acumulación de la "
     "acción de RECLAMACIÓN DE RENTAS, contra [ARRENDATARIO], con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- Contrato de arrendamiento de [vivienda/local] sito en [DIRECCIÓN], de fecha [FECHA], "
     "renta mensual de [IMPORTE] € (Documento nº 1).\n"
     "SEGUNDO.- El arrendatario adeuda las rentas de [MESES], por importe total de [IMPORTE] €.\n"
     "TERCERO.- [Requerimiento de pago previo, si lo hubo].\n\n"
     "FUNDAMENTOS DE DERECHO: LEC arts. 250.1.1 y 437 y ss.; LAU; procedencia del desahucio y de la "
     "reclamación de rentas; enervación (LEC art. 22) en su caso.\n\n"
     "SUPLICO AL JUZGADO que dicte sentencia declarando resuelto el contrato, condenando al demandado "
     "al DESALOJO de la finca y al pago de [IMPORTE] € más las rentas que venzan hasta la entrega, con costas.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("recurso-apelacion-civil", "Recurso de apelación",
     "Modelo de recurso de apelación civil contra sentencia — conforme a LEC arts. 458 y ss.",
     "Elaboración propia — LEC arts. 458 y ss.",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n"
     "(para ante la AUDIENCIA PROVINCIAL DE [PROVINCIA])\n"
     "Autos nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en la representación acreditada, DIGO:\n\n"
     "Que, dentro de plazo, INTERPONGO RECURSO DE APELACIÓN contra la Sentencia de fecha [FECHA], "
     "notificada el [FECHA], por los siguientes\n\n"
     "MOTIVOS\n"
     "PRIMERO.- ERROR EN LA VALORACIÓN DE LA PRUEBA: [explicación].\n"
     "SEGUNDO.- INFRACCIÓN DE NORMAS SUSTANTIVAS/PROCESALES: [precepto infringido y por qué].\n\n"
     "SUPLICO que, previa admisión y traslado a las demás partes, se eleven los autos a la Audiencia "
     "Provincial, que deberá dictar resolución que REVOQUE la sentencia apelada y [PETICIÓN], con costas.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-divorcio-mutuo-acuerdo", "Familia",
     "Modelo de demanda de divorcio de mutuo acuerdo — CC art. 86 y LEC art. 777",
     "Elaboración propia — CC art. 86; LEC art. 777",
     "AL JUZGADO DE PRIMERA INSTANCIA [DE FAMILIA] DE [CIUDAD]\n\n"
     "D./Dña. [CÓNYUGE 1] y D./Dña. [CÓNYUGE 2], ambos mayores de edad, con DNI [COMPLETAR], "
     "representados por el/la Procurador/a [NOMBRE] y asistidos por el/la Letrado/a [NOMBRE], DECIMOS:\n\n"
     "Que de común acuerdo solicitamos el DIVORCIO de nuestro matrimonio, contraído el [FECHA] en "
     "[LUGAR], con base en los siguientes\n\n"
     "HECHOS\n"
     "PRIMERO.- Matrimonio y, en su caso, hijos: [DATOS].\n"
     "SEGUNDO.- Ha transcurrido el plazo legal desde la celebración (CC art. 86).\n"
     "TERCERO.- Se acompaña CONVENIO REGULADOR firmado por ambos (LEC art. 777), que regula: uso de la "
     "vivienda, guarda y custodia y régimen de visitas, pensión de alimentos, pensión compensatoria y "
     "liquidación del régimen económico.\n\n"
     "SUPLICAMOS AL JUZGADO que, previos los trámites, dicte sentencia que declare disuelto por divorcio "
     "el matrimonio y apruebe el convenio regulador acompañado.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado por ambos cónyuges, Procurador/a y Letrado/a."),

    ("solicitud-medidas-cautelares", "Medidas cautelares",
     "Modelo de solicitud de medidas cautelares — conforme a LEC arts. 721 y ss.",
     "Elaboración propia — LEC arts. 721 y ss.",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [SOLICITANTE], DIGO:\n\n"
     "Que, al amparo de los artículos 721 y siguientes de la LEC, SOLICITO LA ADOPCIÓN DE MEDIDAS "
     "CAUTELARES consistentes en [MEDIDA: embargo preventivo / anotación de demanda / prohibición de "
     "disponer / cesación provisional…], con base en los siguientes\n\n"
     "HECHOS Y PRESUPUESTOS\n"
     "PRIMERO.- APARIENCIA DE BUEN DERECHO (fumus boni iuris): [justificación].\n"
     "SEGUNDO.- PELIGRO POR LA MORA PROCESAL (periculum in mora): [justificación].\n"
     "TERCERO.- Ofrecimiento de CAUCIÓN (LEC art. 728.3): [tipo e importe].\n\n"
     "SUPLICO que se acuerden las medidas cautelares interesadas [con/sin audiencia previa], prestada la "
     "caución que se fije.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    # ─────────────────────────── LABORAL ───────────────────────────
    ("papeleta-conciliacion", "Laboral",
     "Modelo de papeleta de conciliación previa (SMAC) — conforme a LRJS art. 63",
     "Elaboración propia — LRJS arts. 63-68",
     "AL SERVICIO DE MEDIACIÓN, ARBITRAJE Y CONCILIACIÓN (SMAC) DE [PROVINCIA]\n\n"
     "D./Dña. [TRABAJADOR], con DNI [COMPLETAR] y domicilio en [DIRECCIÓN], presenta PAPELETA DE "
     "CONCILIACIÓN frente a la empresa [NOMBRE/CIF], con domicilio en [DIRECCIÓN], por [DESPIDO / "
     "RECLAMACIÓN DE CANTIDAD / SANCIÓN / MODIFICACIÓN SUSTANCIAL], exponiendo:\n\n"
     "PRIMERO.- Antigüedad: [FECHA]. Categoría: [COMPLETAR]. Salario: [IMPORTE] € [con prorrata de pagas].\n"
     "SEGUNDO.- Hechos: [relato: fecha y forma del despido / conceptos adeudados y su importe].\n"
     "TERCERO.- Pretensión: [improcedencia/nulidad del despido / abono de [IMPORTE] €].\n\n"
     "SOLICITA que se tenga por presentada la papeleta, se señale acto de conciliación y se cite a la "
     "empresa, teniéndose por intentada sin efecto si no comparece.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-despido", "Laboral",
     "Modelo de demanda por despido ante el Juzgado de lo Social — LRJS arts. 103 y ss.",
     "Elaboración propia — LRJS arts. 80 y 103 y ss.",
     "AL JUZGADO DE LO SOCIAL DE [CIUDAD]\n\n"
     "D./Dña. [TRABAJADOR], con DNI [COMPLETAR] y domicilio en [DIRECCIÓN], [por sí / asistido de "
     "Letrado/Graduado Social], interpone DEMANDA POR DESPIDO frente a [EMPRESA/CIF], con base en:\n\n"
     "HECHOS\n"
     "PRIMERO.- Relación laboral: antigüedad [FECHA], categoría [COMPLETAR], salario [IMPORTE] €/mes con "
     "prorrata de pagas.\n"
     "SEGUNDO.- El [FECHA] la empresa comunicó el despido mediante [carta/verbal], alegando [CAUSA].\n"
     "TERCERO.- El despido es [IMPROCEDENTE/NULO] por [falta de forma / inexistencia de causa / "
     "vulneración de derechos fundamentales].\n"
     "CUARTO.- Se celebró conciliación previa el [FECHA] con resultado [sin avenencia] (se acompaña).\n\n"
     "FUNDAMENTOS DE DERECHO: LRJS arts. 103 y ss.; ET arts. 54-56; [calificación y efectos].\n\n"
     "SUPLICO que se dicte sentencia declarando el despido IMPROCEDENTE o NULO, con las consecuencias "
     "legales (readmisión o indemnización y, en su caso, salarios de tramitación).\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-reclamacion-cantidad-laboral", "Laboral",
     "Modelo de demanda de reclamación de cantidad (laboral) — Juzgado de lo Social",
     "Elaboración propia — LRJS arts. 80 y ss.",
     "AL JUZGADO DE LO SOCIAL DE [CIUDAD]\n\n"
     "D./Dña. [TRABAJADOR], con DNI [COMPLETAR], interpone DEMANDA DE RECLAMACIÓN DE CANTIDAD frente a "
     "[EMPRESA/CIF], con base en:\n\n"
     "HECHOS\n"
     "PRIMERO.- Relación laboral vigente/extinguida: antigüedad [FECHA], categoría, salario.\n"
     "SEGUNDO.- Conceptos adeudados: [salarios de los meses …, pagas extra, horas extra, vacaciones no "
     "disfrutadas…], con detalle y total de [IMPORTE] €.\n"
     "TERCERO.- Conciliación previa intentada el [FECHA].\n\n"
     "SUPLICO que se condene a la empresa demandada a abonar [IMPORTE] €, más el 10% de interés por mora "
     "(ET art. 29.3) en lo que proceda.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    # ─────────────────────────── ADMINISTRATIVO ───────────────────────────
    ("recurso-reposicion-admin", "Administrativo",
     "Modelo de recurso de reposición (administrativo) — Ley 39/2015 arts. 123-124",
     "Elaboración propia — Ley 39/2015 arts. 123-124",
     "A [ÓRGANO ADMINISTRATIVO QUE DICTÓ EL ACTO]\n\n"
     "D./Dña. [INTERESADO], con DNI [COMPLETAR] y domicilio a efectos de notificaciones en [DIRECCIÓN], "
     "ante ese órgano comparece y EXPONE:\n\n"
     "PRIMERO.- Que con fecha [FECHA] se me notificó [RESOLUCIÓN/ACTO], Expediente nº [COMPLETAR].\n"
     "SEGUNDO.- Que, estando disconforme, dentro del plazo de un mes (Ley 39/2015 art. 124) interpongo "
     "RECURSO DE REPOSICIÓN con base en los siguientes motivos: [MOTIVOS DE IMPUGNACIÓN].\n\n"
     "Por lo expuesto, SOLICITO que se tenga por interpuesto el recurso y se dicte resolución que ANULE "
     "o REVOQUE el acto recurrido, [PETICIÓN CONCRETA].\n"
     "OTROSÍ: [solicitud de suspensión del acto conforme a Ley 39/2015 art. 117, si procede].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("recurso-alzada", "Administrativo",
     "Modelo de recurso de alzada (administrativo) — Ley 39/2015 arts. 121-122",
     "Elaboración propia — Ley 39/2015 arts. 121-122",
     "AL [ÓRGANO SUPERIOR JERÁRQUICO] (por conducto del órgano que dictó el acto)\n\n"
     "D./Dña. [INTERESADO], con DNI [COMPLETAR], EXPONE:\n\n"
     "PRIMERO.- Que se me notificó el [FECHA] [ACTO/RESOLUCIÓN no definitivo en vía administrativa], "
     "Expediente nº [COMPLETAR].\n"
     "SEGUNDO.- Que, dentro del plazo de un mes (Ley 39/2015 art. 122), interpongo RECURSO DE ALZADA "
     "por los siguientes motivos: [MOTIVOS].\n\n"
     "SOLICITO que se estime el recurso y se ANULE el acto recurrido, [PETICIÓN].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("reclamacion-responsabilidad-patrimonial", "Administrativo",
     "Modelo de reclamación de responsabilidad patrimonial de la Administración — Ley 39/2015 y 40/2015",
     "Elaboración propia — Ley 39/2015; Ley 40/2015 arts. 32 y ss.",
     "A [ADMINISTRACIÓN COMPETENTE]\n\n"
     "D./Dña. [RECLAMANTE], con DNI [COMPLETAR], EXPONE:\n\n"
     "PRIMERO.- Que como consecuencia del funcionamiento [normal/anormal] de los servicios públicos he "
     "sufrido el siguiente daño: [DESCRIPCIÓN], el día [FECHA], en [LUGAR].\n"
     "SEGUNDO.- RELACIÓN DE CAUSALIDAD entre el daño y el servicio público: [explicación].\n"
     "TERCERO.- EVALUACIÓN ECONÓMICA del daño: [IMPORTE] € (se acompañan justificantes).\n\n"
     "FUNDAMENTOS: Ley 40/2015 arts. 32 y ss. (responsabilidad patrimonial); daño efectivo, evaluable e "
     "individualizado; antijuridicidad.\n\n"
     "SOLICITO que se tramite la reclamación y se reconozca una indemnización de [IMPORTE] €.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("recurso-contencioso-interposicion", "Administrativo",
     "Modelo de escrito de interposición de recurso contencioso-administrativo — LJCA arts. 45 y ss.",
     "Elaboración propia — LJCA arts. 45 y ss.",
     "A LA SALA DE LO CONTENCIOSO-ADMINISTRATIVO DEL [TRIBUNAL] / AL JUZGADO DE LO "
     "CONTENCIOSO-ADMINISTRATIVO DE [CIUDAD]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [RECURRENTE], DIGO:\n\n"
     "Que, al amparo de los artículos 45 y ss. de la LJCA, INTERPONGO RECURSO CONTENCIOSO-ADMINISTRATIVO "
     "contra [DISPOSICIÓN/ACTO/INACTIVIDAD] de [ADMINISTRACIÓN], de fecha [FECHA].\n\n"
     "Se acompaña [el acto impugnado / la resolución que agota la vía administrativa] y el documento que "
     "acredita la representación.\n\n"
     "SUPLICO que se tenga por interpuesto el recurso, se reclame el expediente administrativo y se me dé "
     "traslado para formalizar demanda.\n"
     "OTROSÍ: [medida cautelar de suspensión conforme a LJCA arts. 129 y ss., si procede].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("alegaciones-procedimiento-admin", "Administrativo",
     "Modelo de escrito de alegaciones en procedimiento administrativo — Ley 39/2015 art. 76 y 82",
     "Elaboración propia — Ley 39/2015 arts. 53, 76 y 82",
     "A [ÓRGANO INSTRUCTOR]\n\n"
     "D./Dña. [INTERESADO], en el Expediente nº [COMPLETAR], dentro del trámite de [alegaciones / "
     "audiencia], EXPONE:\n\n"
     "PRIMERO.- [Alegaciones de hecho].\n"
     "SEGUNDO.- [Alegaciones de derecho].\n"
     "TERCERO.- [Documentos y, en su caso, proposición de prueba].\n\n"
     "SOLICITA que se tengan por formuladas estas alegaciones y se dicte resolución [PETICIÓN].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    # ─────────────────────────── PENAL (ampliación) ───────────────────────────
    ("recurso-reforma-penal", "Recurso de reforma",
     "Modelo de recurso de reforma contra auto (penal) — conforme a LECrim arts. 211 y 766",
     "Elaboración propia — LECrim arts. 211, 217 y 766",
     "AL JUZGADO DE INSTRUCCIÓN Nº [COMPLETAR] DE [CIUDAD]\n"
     "Diligencias [Previas/Sumario] nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [PARTE], DIGO:\n\n"
     "Que, dentro de plazo, interpongo RECURSO DE REFORMA [y subsidiario de apelación] contra el Auto de "
     "fecha [FECHA], notificado el [FECHA], por los siguientes motivos: [MOTIVOS].\n\n"
     "SUPLICO que, estimando el recurso, se DEJE SIN EFECTO el auto recurrido y se acuerde [PETICIÓN].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("personacion-acusacion-particular", "Acusación particular",
     "Modelo de escrito de personación como acusación particular — LECrim arts. 109-110",
     "Elaboración propia — LECrim arts. 109-110",
     "AL JUZGADO DE INSTRUCCIÓN Nº [COMPLETAR] DE [CIUDAD]\n"
     "Diligencias Previas nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [PERJUDICADO/VÍCTIMA], bajo dirección letrada de [ABOGADO], DIGO:\n\n"
     "Que, al amparo de los artículos 109 y 110 de la LECrim, mediante este escrito me PERSONO en las "
     "presentes diligencias como ACUSACIÓN PARTICULAR, en nombre de mi representado, ofendido/perjudicado "
     "por los hechos investigados.\n\n"
     "SUPLICO que se me tenga por personado y parte, entendiéndose conmigo las sucesivas actuaciones, y se "
     "me dé traslado de lo actuado.\n"
     "OTROSÍ: intereso la práctica de las siguientes diligencias: [DILIGENCIAS].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("escrito-conformidad-penal", "Conformidad",
     "Modelo de escrito de conformidad (penal) — conforme a LECrim art. 787",
     "Elaboración propia — LECrim arts. 655 y 787",
     "AL JUZGADO DE LO PENAL Nº [COMPLETAR] DE [CIUDAD] / A LA AUDIENCIA PROVINCIAL\n"
     "Procedimiento Abreviado nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre del acusado [NOMBRE], bajo dirección letrada de [ABOGADO], DIGO:\n\n"
     "Que, de conformidad con el Ministerio Fiscal [y las demás acusaciones], esta defensa manifiesta su "
     "CONFORMIDAD con el escrito de acusación, aceptando los hechos, la calificación y la pena solicitada "
     "de [PENA], conforme al artículo 787 de la LECrim.\n\n"
     "SUPLICO que se dicte sentencia de conformidad en los términos expresados.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado por el Letrado y el acusado."),

    # ─────────────────────────── CONTRATOS ───────────────────────────
    ("contrato-arrendamiento-vivienda", "Contrato",
     "Modelo de contrato de arrendamiento de vivienda — conforme a la LAU (Ley 29/1994)",
     "Elaboración propia — Ley 29/1994 (LAU)",
     "CONTRATO DE ARRENDAMIENTO DE VIVIENDA\n\n"
     "En [CIUDAD], a [FECHA].\n\n"
     "REUNIDOS: De una parte, D./Dña. [ARRENDADOR], DNI [COMPLETAR] (en adelante, el ARRENDADOR); y de "
     "otra, D./Dña. [ARRENDATARIO], DNI [COMPLETAR] (en adelante, el ARRENDATARIO).\n\n"
     "EXPONEN que el arrendador es propietario de la vivienda sita en [DIRECCIÓN], referencia catastral "
     "[COMPLETAR], y acuerdan su arrendamiento con arreglo a las siguientes\n\n"
     "CLÁUSULAS\n"
     "PRIMERA. OBJETO. Arrendamiento de la vivienda descrita, para uso de residencia habitual.\n"
     "SEGUNDA. DURACIÓN. [PLAZO] años, con las prórrogas legales previstas en la LAU.\n"
     "TERCERA. RENTA. [IMPORTE EN CIFRA Y LETRA] € mensuales, pagaderos [FORMA/FECHA], actualizables "
     "conforme a [ÍNDICE PACTADO/LEGAL].\n"
     "CUARTA. FIANZA. [IMPORTE] € (equivalente a [N] mensualidad/es), depositada conforme a la normativa "
     "autonómica.\n"
     "QUINTA. GASTOS. [Servicios, suministros y comunidad: a cargo de quién].\n"
     "SEXTA. CONSERVACIÓN Y OBRAS. [Régimen].\n"
     "SÉPTIMA. RESOLUCIÓN. Causas de resolución conforme a la LAU y al Código Civil.\n\n"
     "Y en prueba de conformidad, firman por duplicado en el lugar y fecha indicados.\n"
     "EL ARRENDADOR                    EL ARRENDATARIO"),

    ("contrato-compraventa", "Contrato",
     "Modelo de contrato de compraventa — conforme al Código Civil arts. 1445 y ss.",
     "Elaboración propia — CC arts. 1445 y ss.",
     "CONTRATO DE COMPRAVENTA\n\n"
     "En [CIUDAD], a [FECHA].\n\n"
     "REUNIDOS: De una parte, D./Dña. [VENDEDOR], DNI [COMPLETAR] (VENDEDOR); de otra, D./Dña. "
     "[COMPRADOR], DNI [COMPLETAR] (COMPRADOR).\n\n"
     "EXPONEN que el vendedor es titular de [DESCRIPCIÓN DEL BIEN] y que ambas partes convienen su "
     "compraventa con sujeción a las siguientes\n\n"
     "CLÁUSULAS\n"
     "PRIMERA. OBJETO. El vendedor vende y el comprador compra [BIEN], libre de cargas y gravámenes.\n"
     "SEGUNDA. PRECIO. [IMPORTE EN CIFRA Y LETRA] €, que se abona [forma y plazo de pago].\n"
     "TERCERA. ENTREGA. [Lugar, fecha y forma de entrega y transmisión de la posesión].\n"
     "CUARTA. SANEAMIENTO. El vendedor responde de la evicción y de los vicios ocultos (CC arts. 1474 y ss.).\n"
     "QUINTA. GASTOS E IMPUESTOS. [Reparto conforme a lo pactado y a la ley].\n\n"
     "Y en prueba de conformidad, firman por duplicado.\n"
     "EL VENDEDOR                      EL COMPRADOR"),

    ("contrato-prestacion-servicios", "Contrato",
     "Modelo de contrato de prestación de servicios (arrendamiento de servicios)",
     "Elaboración propia — CC arts. 1583 y ss.",
     "CONTRATO DE PRESTACIÓN DE SERVICIOS\n\n"
     "En [CIUDAD], a [FECHA]. REUNIDOS: [CLIENTE] y [PRESTADOR/PROFESIONAL], con los datos que constan.\n\n"
     "CLÁUSULAS\n"
     "PRIMERA. OBJETO. El prestador se obliga a [DESCRIPCIÓN DE LOS SERVICIOS].\n"
     "SEGUNDA. DURACIÓN. [Plazo / por obra / indefinido con preaviso].\n"
     "TERCERA. PRECIO Y FACTURACIÓN. [IMPORTE] € [+ IVA], con la periodicidad y forma de pago de [DETALLE].\n"
     "CUARTA. OBLIGACIONES DE LAS PARTES. [Medios, confidencialidad, entregables].\n"
     "QUINTA. PROPIEDAD INTELECTUAL / CONFIDENCIALIDAD. [Régimen].\n"
     "SEXTA. RESOLUCIÓN Y RESPONSABILIDAD. [Causas y límites].\n"
     "SÉPTIMA. PROTECCIÓN DE DATOS. Conforme al RGPD y la LOPDGDD.\n\n"
     "Y en prueba de conformidad, firman por duplicado.\n"
     "EL CLIENTE                       EL PRESTADOR"),

    ("acuerdo-confidencialidad-nda", "Contrato",
     "Modelo de acuerdo de confidencialidad (NDA)",
     "Elaboración propia — libertad de pactos (CC art. 1255)",
     "ACUERDO DE CONFIDENCIALIDAD (NDA)\n\n"
     "En [CIUDAD], a [FECHA]. Entre [PARTE A] y [PARTE B] (las PARTES).\n\n"
     "CLÁUSULAS\n"
     "PRIMERA. FINALIDAD. Regular el intercambio de información confidencial para [FINALIDAD].\n"
     "SEGUNDA. INFORMACIÓN CONFIDENCIAL. Toda la revelada entre las partes, en cualquier soporte, "
     "excepto la que sea de dominio público o de obtención lícita independiente.\n"
     "TERCERA. OBLIGACIONES. No divulgar ni usar la información para fines distintos; adoptar medidas de "
     "seguridad razonables; devolverla o destruirla a requerimiento.\n"
     "CUARTA. DURACIÓN. La obligación de confidencialidad se mantendrá [PLAZO] años tras el fin de la "
     "relación.\n"
     "QUINTA. INCUMPLIMIENTO. Dará derecho a [indemnización por daños / medidas cautelares].\n\n"
     "Y en prueba de conformidad, firman por duplicado.\n"
     "PARTE A                          PARTE B"),

    # ─────────────────────────── EXTRAJUDICIAL / LABORAL-EMPRESA ──────────────
    ("burofax-requerimiento-pago", "Extrajudicial",
     "Modelo de requerimiento extrajudicial de pago (burofax)",
     "Elaboración propia — reclamación extrajudicial; CC art. 1100 (mora)",
     "REQUERIMIENTO EXTRAJUDICIAL DE PAGO (remitir por BUROFAX con acuse y certificación de texto)\n\n"
     "Remitente: [NOMBRE/CIF], domicilio [DIRECCIÓN].\n"
     "Destinatario: [DEUDOR], domicilio [DIRECCIÓN].\n"
     "En [CIUDAD], a [FECHA].\n\n"
     "Muy Sr./a. mío/a:\n\n"
     "Por medio del presente le REQUIERO FORMALMENTE para que, en el plazo de [N] días, abone la cantidad "
     "de [IMPORTE EN CIFRA Y LETRA] €, que adeuda en concepto de [CONCEPTO: factura nº …/contrato de …], "
     "vencida e impagada pese a mis anteriores gestiones.\n\n"
     "De no atender este requerimiento, me veré obligado/a a reclamar judicialmente la deuda, con los "
     "intereses de demora (CC art. 1100 y ss.) y las costas que se devenguen, sin más aviso.\n\n"
     "Sirva el presente como requerimiento fehaciente a todos los efectos legales.\n\n"
     "Atentamente, [FIRMA Y NOMBRE]."),

    ("reclamacion-extrajudicial", "Extrajudicial",
     "Modelo de reclamación extrajudicial (reclamación previa / interrupción de la prescripción)",
     "Elaboración propia — CC art. 1973 (interrupción de la prescripción)",
     "RECLAMACIÓN EXTRAJUDICIAL\n\n"
     "Remitente: [NOMBRE]. Destinatario: [RECLAMADO]. En [CIUDAD], a [FECHA].\n\n"
     "Por la presente le reclamo [DERECHO/CANTIDAD/PRESTACIÓN], por los siguientes motivos: [HECHOS Y "
     "FUNDAMENTO].\n\n"
     "Le requiero para que, en el plazo de [N] días, [cumpla/abone/subsane]. Esta reclamación interrumpe "
     "la prescripción de la acción (CC art. 1973).\n\n"
     "Atentamente, [FIRMA Y NOMBRE]."),

    ("carta-despido-disciplinario", "Laboral",
     "Modelo de carta de despido disciplinario — conforme al Estatuto de los Trabajadores arts. 54-55",
     "Elaboración propia — ET arts. 54-55",
     "COMUNICACIÓN DE DESPIDO DISCIPLINARIO\n\n"
     "Empresa: [NOMBRE/CIF]. Trabajador/a: [NOMBRE], DNI [COMPLETAR]. En [CIUDAD], a [FECHA].\n\n"
     "Muy Sr./a.:\n\n"
     "La dirección de esta empresa le comunica su DESPIDO DISCIPLINARIO con efectos del día [FECHA], al "
     "amparo del artículo 54 del Estatuto de los Trabajadores, por los siguientes HECHOS: [DESCRIPCIÓN "
     "DETALLADA, CON FECHAS, DE LAS CONDUCTAS IMPUTADAS] que constituyen [causa concreta del art. 54.2].\n\n"
     "Queda a su disposición la liquidación de las partes proporcionales que le corresponden. Podrá "
     "impugnar esta decisión conforme a la normativa laboral.\n\n"
     "Recibí (firma del trabajador, a efectos de notificación): ____________   La empresa: ____________"),

    ("finiquito", "Laboral",
     "Modelo de recibo de finiquito",
     "Elaboración propia — ET art. 49",
     "RECIBO DE FINIQUITO\n\n"
     "D./Dña. [TRABAJADOR], DNI [COMPLETAR], que ha prestado servicios para [EMPRESA/CIF] desde [FECHA] "
     "hasta [FECHA], con categoría [COMPLETAR], DECLARA:\n\n"
     "Que recibe de la empresa la cantidad de [IMPORTE EN CIFRA Y LETRA] €, por los siguientes conceptos: "
     "salario de los días trabajados del mes, parte proporcional de pagas extraordinarias, vacaciones no "
     "disfrutadas [y, en su caso, indemnización], según el detalle adjunto.\n\n"
     "Con el percibo de dicha cantidad, [y sin perjuicio de la posible impugnación del despido,] declara "
     "saldada y finiquitada la relación laboral.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado: El trabajador / La empresa."),

    ("reclamacion-consumo", "Extrajudicial",
     "Modelo de reclamación de consumo (hoja de reclamaciones / reclamación a empresa)",
     "Elaboración propia — normativa de consumidores y usuarios (RDL 1/2007)",
     "RECLAMACIÓN DE CONSUMO\n\n"
     "Consumidor: [NOMBRE, DNI, DIRECCIÓN, CONTACTO]. Empresa reclamada: [NOMBRE/CIF]. En [CIUDAD], a [FECHA].\n\n"
     "HECHOS: El [FECHA] contraté/adquirí [PRODUCTO/SERVICIO] por importe de [IMPORTE] €. [DESCRIPCIÓN DEL "
     "PROBLEMA: defecto, incumplimiento, cobro indebido, falta de información…].\n\n"
     "PRETENSIÓN: Solicito [reparación / sustitución / devolución del importe / rebaja del precio / "
     "resolución del contrato e indemnización], conforme a la normativa de consumidores.\n\n"
     "Si en el plazo de [N] días no obtengo respuesta satisfactoria, acudiré a la Junta Arbitral de "
     "Consumo y/o a los organismos de consumo competentes.\n\n"
     "Firmado: [NOMBRE]."),

    # ─────────────────────────── PROCESALES COMUNES ───────────────────────────
    ("escrito-personacion", "Escrito procesal",
     "Modelo de escrito de personación en un procedimiento",
     "Elaboración propia — personación y representación procesal",
     "AL [JUZGADO/TRIBUNAL] DE [CIUDAD]\n"
     "Procedimiento nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [PARTE], según acredito con [poder/designación], DIGO:\n\n"
     "Que, mediante el presente escrito, me PERSONO en el procedimiento de referencia en la "
     "representación indicada, solicitando se me tenga por parte y se entiendan conmigo las sucesivas "
     "diligencias.\n\n"
     "SUPLICO que se tenga por efectuada la personación y por parte a esta representación.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("solicitud-justicia-gratuita", "Escrito procesal",
     "Modelo de solicitud de asistencia jurídica gratuita — Ley 1/1996",
     "Elaboración propia — Ley 1/1996 de Asistencia Jurídica Gratuita",
     "A LA COMISIÓN DE ASISTENCIA JURÍDICA GRATUITA DE [PROVINCIA] / AL COLEGIO DE ABOGADOS DE [CIUDAD]\n\n"
     "D./Dña. [SOLICITANTE], con DNI [COMPLETAR], domicilio en [DIRECCIÓN], SOLICITA el reconocimiento del "
     "derecho a la ASISTENCIA JURÍDICA GRATUITA, con base en:\n\n"
     "PRIMERO.- Que carezco de recursos suficientes para litigar, no superando mi unidad familiar los "
     "umbrales del IPREM exigidos por la Ley 1/1996.\n"
     "SEGUNDO.- Que preciso defensa/representación en [ASUNTO].\n"
     "TERCERO.- Se acompañan: DNI, declaración de la renta/certificado de ingresos, certificado de "
     "empadronamiento y [DOCUMENTACIÓN ACREDITATIVA].\n\n"
     "SOLICITA que se reconozca el derecho y se designe Abogado y Procurador del turno de oficio.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("escrito-proposicion-prueba", "Escrito procesal",
     "Modelo de escrito de proposición de prueba",
     "Elaboración propia — proposición de prueba (LEC/LECrim según orden)",
     "AL [JUZGADO/TRIBUNAL] DE [CIUDAD]\n"
     "Procedimiento nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [PARTE], DIGO:\n\n"
     "Que, dentro del trámite correspondiente, PROPONGO los siguientes MEDIOS DE PRUEBA:\n"
     "1.- DOCUMENTAL: [documentos nº …].\n"
     "2.- INTERROGATORIO de [parte/testigo].\n"
     "3.- TESTIFICAL: [testigos y domicilios].\n"
     "4.- PERICIAL: [objeto y perito].\n"
     "5.- [OTROS].\n\n"
     "SUPLICO que se admitan los medios de prueba propuestos por ser pertinentes y útiles.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("escrito-subsanacion", "Escrito procesal",
     "Modelo de escrito de subsanación de defectos",
     "Elaboración propia — subsanación de defectos procesales/administrativos",
     "AL [JUZGADO/TRIBUNAL/ÓRGANO] DE [CIUDAD]\n"
     "Procedimiento/Expediente nº [COMPLETAR]\n\n"
     "D./Dña. [PARTE/PROCURADOR] DIGO:\n\n"
     "Que, habiéndoseme requerido para subsanar [DEFECTO INDICADO] mediante [resolución/notificación] de "
     "fecha [FECHA], y dentro del plazo concedido, procedo a SUBSANAR acompañando [DOCUMENTO/ACTO DE "
     "SUBSANACIÓN].\n\n"
     "SUPLICO que se tenga por subsanado el defecto y por cumplimentado el requerimiento, continuando el "
     "procedimiento.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("solicitud-aplazamiento-fraccionamiento", "Administrativo",
     "Modelo de solicitud de aplazamiento o fraccionamiento de deuda",
     "Elaboración propia — aplazamiento/fraccionamiento (normativa recaudatoria)",
     "A [ADMINISTRACIÓN/ORGANISMO RECAUDADOR]\n\n"
     "D./Dña. [INTERESADO], con DNI/CIF [COMPLETAR], EXPONE:\n\n"
     "PRIMERO.- Que tengo pendiente de pago la deuda [REFERENCIA/LIQUIDACIÓN nº …], por importe de "
     "[IMPORTE] €.\n"
     "SEGUNDO.- Que, por dificultades [económicas/transitorias de tesorería], no puedo afrontar el pago "
     "en el plazo previsto.\n\n"
     "SOLICITA el [APLAZAMIENTO hasta [FECHA] / FRACCIONAMIENTO en [N] plazos] de la deuda, ofreciendo, en "
     "su caso, [garantía], y comprometiéndose al pago en los términos que se acuerden.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("autorizacion-representacion", "General",
     "Modelo de autorización / representación para trámites",
     "Elaboración propia — representación voluntaria (CC art. 1709; Ley 39/2015 art. 5)",
     "AUTORIZACIÓN\n\n"
     "D./Dña. [AUTORIZANTE], con DNI [COMPLETAR] y domicilio en [DIRECCIÓN], por medio del presente "
     "AUTORIZO a D./Dña. [AUTORIZADO], con DNI [COMPLETAR], para que en mi nombre y representación realice "
     "el siguiente trámite: [DESCRIPCIÓN DEL TRÁMITE/GESTIÓN] ante [ORGANISMO/ENTIDAD].\n\n"
     "Y para que así conste, firmo la presente autorización.\n\n"
     "En [CIUDAD], a [FECHA].\n"
     "El autorizante: ____________   (Se acompaña copia del DNI de ambas partes)."),

    # ─────────────────────────── MERCANTIL ───────────────────────────
    ("solicitud-concurso-acreedores", "Mercantil",
     "Modelo de solicitud de declaración de concurso (voluntario)",
     "Elaboración propia — Texto Refundido Ley Concursal (RDL 1/2020)",
     "AL JUZGADO DE LO MERCANTIL DE [CIUDAD]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [DEUDOR/SOCIEDAD, CIF], bajo dirección letrada de [ABOGADO], DIGO:\n\n"
     "Que, al amparo de la Ley Concursal, SOLICITO la declaración de CONCURSO VOLUNTARIO de mi "
     "representado, por encontrarse en estado de [insolvencia actual/inminente], con base en:\n\n"
     "HECHOS\n"
     "PRIMERO.- Identificación del deudor y actividad.\n"
     "SEGUNDO.- Estado de insolvencia: [imposibilidad de cumplir regularmente las obligaciones exigibles].\n"
     "TERCERO.- Se acompañan: memoria económica, inventario de bienes y derechos, relación de acreedores, "
     "y cuentas anuales [si procede].\n\n"
     "SUPLICO que se declare el concurso de [DEUDOR] y se adopten las medidas legales procedentes.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("reclamacion-mercantil-factura", "Mercantil",
     "Modelo de reclamación de deuda mercantil (facturas impagadas entre empresas)",
     "Elaboración propia — Ley 3/2004 de morosidad en operaciones comerciales",
     "RECLAMACIÓN DE DEUDA MERCANTIL\n\n"
     "De [EMPRESA ACREEDORA/CIF] a [EMPRESA DEUDORA/CIF]. En [CIUDAD], a [FECHA].\n\n"
     "Les reclamamos el importe de [IMPORTE EN CIFRA Y LETRA] €, correspondiente a las facturas "
     "[NÚMEROS Y FECHAS], vencidas e impagadas, derivadas del contrato/pedido de [OBJETO].\n\n"
     "Conforme a la Ley 3/2004 de lucha contra la morosidad, procede además el interés de demora y la "
     "compensación por costes de cobro. Les requerimos el pago en [N] días; en su defecto reclamaremos "
     "judicialmente (proceso monitorio/ordinario) con intereses y costas.\n\n"
     "Atentamente, [FIRMA Y CARGO]."),

    # ─────────────────────────── HERENCIAS / FAMILIA ───────────────────────────
    ("aceptacion-herencia", "Herencias",
     "Modelo de escrito de aceptación de herencia (a beneficio de inventario o pura y simple)",
     "Elaboración propia — CC arts. 988 y ss.",
     "ACEPTACIÓN DE HERENCIA\n\n"
     "D./Dña. [HEREDERO], con DNI [COMPLETAR], en relación con la herencia causada por el fallecimiento de "
     "D./Dña. [CAUSANTE] el [FECHA], DECLARA:\n\n"
     "PRIMERO.- Que es llamado a la herencia en condición de [heredero testamentario / ab intestato], según "
     "[testamento ante Notario … / declaración de herederos].\n"
     "SEGUNDO.- Que ACEPTA la herencia [pura y simplemente / A BENEFICIO DE INVENTARIO conforme a los "
     "arts. 1010 y ss. del Código Civil].\n\n"
     "[Para formalizar en escritura pública ante Notario, acompañando certificado de defunción, de últimas "
     "voluntades y el título sucesorio.]\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("solicitud-declaracion-herederos", "Herencias",
     "Modelo de solicitud de declaración de herederos abintestato (acta notarial)",
     "Elaboración propia — CC arts. 912 y ss.; Ley del Notariado",
     "AL NOTARIO DE [CIUDAD]\n\n"
     "D./Dña. [SOLICITANTE], con DNI [COMPLETAR], SOLICITA la tramitación de ACTA DE NOTORIEDAD de "
     "DECLARACIÓN DE HEREDEROS ABINTESTATO por fallecimiento de D./Dña. [CAUSANTE], ocurrido el [FECHA] "
     "en [LUGAR], sin haber otorgado testamento, exponiendo:\n\n"
     "PRIMERO.- Parentesco del solicitante y demás interesados con el causante.\n"
     "SEGUNDO.- Relación de posibles herederos: [NOMBRES Y PARENTESCO].\n"
     "TERCERO.- Se acompañan: certificado de defunción, de últimas voluntades, libro de familia y "
     "[documentación acreditativa del parentesco].\n\n"
     "SOLICITA que se tramite el acta y se declaren herederos a quienes legalmente corresponda.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-alimentos", "Familia",
     "Modelo de demanda de alimentos",
     "Elaboración propia — CC arts. 142 y ss.; LEC",
     "AL JUZGADO DE PRIMERA INSTANCIA [DE FAMILIA] DE [CIUDAD]\n\n"
     "D./Dña. [DEMANDANTE], en nombre propio [y/o en representación de los hijos menores], DICE:\n\n"
     "Que formula DEMANDA DE ALIMENTOS contra D./Dña. [DEMANDADO], obligado conforme a los artículos 142 "
     "y siguientes del Código Civil, con base en:\n\n"
     "HECHOS\n"
     "PRIMERO.- Vínculo que genera la obligación de alimentos [parentesco].\n"
     "SEGUNDO.- Necesidad del alimentista y posibilidades económicas del alimentante.\n"
     "TERCERO.- Cuantía solicitada: [IMPORTE] €/mes, actualizable conforme al IPC.\n\n"
     "SUPLICO que se condene al demandado a abonar una pensión de alimentos de [IMPORTE] €/mes, con efectos "
     "desde la interposición de la demanda.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("solicitud-modificacion-medidas", "Familia",
     "Modelo de demanda de modificación de medidas (divorcio/guarda)",
     "Elaboración propia — CC art. 90-91; LEC art. 775",
     "AL JUZGADO DE PRIMERA INSTANCIA [DE FAMILIA] DE [CIUDAD]\n"
     "Autos de [divorcio/medidas] nº [COMPLETAR]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [SOLICITANTE], DIGO:\n\n"
     "Que, al amparo del artículo 775 de la LEC, solicito la MODIFICACIÓN DE LAS MEDIDAS acordadas en "
     "[sentencia/convenio] de fecha [FECHA], por haberse producido una ALTERACIÓN SUSTANCIAL de las "
     "circunstancias, consistente en: [CAMBIO: ingresos, traslado, necesidades de los hijos…].\n\n"
     "SUPLICO que se modifiquen las medidas en el siguiente sentido: [NUEVA PENSIÓN / NUEVO RÉGIMEN DE "
     "GUARDA Y VISITAS / USO DE VIVIENDA].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("solicitud-orden-proteccion", "Penal",
     "Modelo de solicitud de orden de protección (víctima de violencia)",
     "Elaboración propia — LECrim art. 544 ter",
     "AL JUZGADO DE [VIOLENCIA SOBRE LA MUJER / INSTRUCCIÓN DE GUARDIA] DE [CIUDAD]\n\n"
     "D./Dña. [VÍCTIMA], con DNI [COMPLETAR], SOLICITA ORDEN DE PROTECCIÓN al amparo del artículo 544 ter "
     "de la LECrim, exponiendo:\n\n"
     "PRIMERO.- Relación con el denunciado: [vínculo].\n"
     "SEGUNDO.- Hechos y situación de riesgo: [DESCRIPCIÓN DE LOS HECHOS, FECHAS Y AMENAZAS].\n"
     "TERCERO.- Medidas que se solicitan: [alejamiento, prohibición de comunicación, atribución del uso de "
     "la vivienda, medidas civiles sobre hijos y pensión].\n\n"
     "SUPLICA que se acuerde la orden de protección con las medidas penales y civiles interesadas, con "
     "carácter urgente.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    # ─────────────────────────── PROPIEDAD HORIZONTAL ───────────────────────────
    ("impugnacion-acuerdos-comunidad", "Propiedad horizontal",
     "Modelo de demanda de impugnación de acuerdos de la junta de propietarios",
     "Elaboración propia — Ley 49/1960 de Propiedad Horizontal art. 18",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [PROPIETARIO], con DNI [COMPLETAR], propietario del piso/local [IDENTIFICACIÓN] de la "
     "comunidad sita en [DIRECCIÓN], interpone DEMANDA DE IMPUGNACIÓN DE ACUERDOS, con base en:\n\n"
     "HECHOS\n"
     "PRIMERO.- En junta de [FECHA] se adoptó el acuerdo: [DESCRIPCIÓN], que impugno.\n"
     "SEGUNDO.- Motivos de impugnación (LPH art. 18): [contrario a la ley/estatutos / gravemente lesivo / "
     "abuso de derecho], y estoy al corriente de pago o he consignado las deudas.\n\n"
     "SUPLICO que se declare la NULIDAD del acuerdo impugnado, con costas a la comunidad demandada.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("reclamacion-cuotas-comunidad", "Propiedad horizontal",
     "Modelo de reclamación de cuotas impagadas de comunidad (monitorio de comunidad)",
     "Elaboración propia — LPH art. 21; LEC art. 812 y ss.",
     "AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]\n\n"
     "D./Dña. [PRESIDENTE/ADMINISTRADOR], en nombre de la COMUNIDAD DE PROPIETARIOS de [DIRECCIÓN], "
     "formula PETICIÓN INICIAL DE PROCESO MONITORIO frente a D./Dña. [PROPIETARIO DEUDOR], exponiendo:\n\n"
     "PRIMERO.- El demandado adeuda cuotas de comunidad por importe de [IMPORTE] €, aprobadas en junta y "
     "liquidadas conforme al artículo 21 de la LPH (se acompaña certificación del acuerdo y la deuda).\n\n"
     "SUPLICO que se requiera de pago al deudor de [IMPORTE] € más intereses y, en su caso, costas.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    # ─────────────────────────── EXTRANJERÍA / TRÁFICO / CONSUMO ──────────────
    ("solicitud-arraigo", "Extranjería",
     "Modelo de solicitud de autorización de residencia por arraigo",
     "Elaboración propia — Ley Orgánica 4/2000 y su Reglamento",
     "A LA OFICINA DE EXTRANJERÍA DE [PROVINCIA]\n\n"
     "D./Dña. [SOLICITANTE], con NIE/pasaporte [COMPLETAR], SOLICITA autorización de residencia temporal "
     "por circunstancias excepcionales (ARRAIGO [social/laboral/familiar/formativo]), exponiendo:\n\n"
     "PRIMERO.- Permanencia continuada en España desde [FECHA] (se acompaña prueba: empadronamiento, etc.).\n"
     "SEGUNDO.- [Vínculos familiares / contrato o medios de vida / informe de arraigo del Ayuntamiento].\n"
     "TERCERO.- Carencia de antecedentes penales.\n\n"
     "SOLICITA que se conceda la autorización de residencia por arraigo, con la documentación aportada.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("alegaciones-multa-trafico", "Tráfico",
     "Modelo de alegaciones / recurso contra sanción de tráfico",
     "Elaboración propia — RDL 6/2015 (Ley de Tráfico); Ley 39/2015",
     "A LA [JEFATURA PROVINCIAL DE TRÁFICO / AYUNTAMIENTO DE [CIUDAD]]\n\n"
     "D./Dña. [INTERESADO], con DNI [COMPLETAR], en relación con el expediente sancionador nº [COMPLETAR] "
     "por [INFRACCIÓN], formula ALEGACIONES [o RECURSO DE REPOSICIÓN si ya hay resolución], exponiendo:\n\n"
     "PRIMERO.- [Hechos: por qué no se cometió la infracción / defectos en la notificación / error en los "
     "datos / falta de prueba / prescripción].\n"
     "SEGUNDO.- [Fundamentos: garantías del procedimiento sancionador, presunción de inocencia].\n\n"
     "SOLICITA que se ARCHIVE el expediente o se ANULE la sanción.\n"
     "OTROSÍ: propongo como prueba [fotografías, testigos, informe técnico].\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),

    ("demanda-clausulas-abusivas", "Consumo",
     "Modelo de demanda por cláusulas abusivas (nulidad y reclamación de cantidades)",
     "Elaboración propia — RDL 1/2007 (consumidores); Directiva 93/13/CEE",
     "AL JUZGADO [DE PRIMERA INSTANCIA / DE LO MERCANTIL] DE [CIUDAD]\n\n"
     "D./Dña. [PROCURADOR], en nombre de [CONSUMIDOR], DICE:\n\n"
     "Que formula DEMANDA contra [ENTIDAD], solicitando la declaración de NULIDAD por abusiva de la "
     "cláusula [IDENTIFICACIÓN: suelo / gastos / comisión / interés…] del contrato de [FECHA], y la "
     "restitución de las cantidades indebidamente cobradas, con base en:\n\n"
     "HECHOS\n"
     "PRIMERO.- Contrato suscrito como consumidor: [datos].\n"
     "SEGUNDO.- Cláusula impugnada y su carácter abusivo (falta de transparencia / desequilibrio).\n"
     "TERCERO.- Importes cobrados en aplicación de la cláusula: [IMPORTE] €.\n\n"
     "SUPLICO que se declare la nulidad de la cláusula y se condene a la demandada a restituir [IMPORTE] € "
     "más intereses, con costas.\n\n"
     "En [CIUDAD], a [FECHA]. Firmado."),
]


def main():
    if not os.path.exists(INDEX):
        print(f"ERROR: no existe {INDEX}", file=sys.stderr)
        sys.exit(1)

    with open(INDEX, encoding="utf-8") as fh:
        data = json.load(fh)
    frags = data.get("fragmentos", [])

    existentes = {f.get("articulo") for f in frags if f.get("abrev") == "MEP"}
    nuevos = 0
    for slug, capitulo, titulo, fuente, texto in MODELOS:
        if slug in existentes:
            continue
        frags.append({
            "ley": "Modelos de Escritos Procesales",
            "abrev": "MEP",
            "boe_id": None,
            "articulo": slug,
            "titulo": titulo,
            "capitulo": capitulo,
            "seccion": None,
            "texto": texto,
            "fuente_url": fuente,
            "fecha_consolidada": "2026",
        })
        existentes.add(slug)
        nuevos += 1

    data["fragmentos"] = frags
    data["total_fragmentos"] = len(frags)

    if nuevos:
        backup = INDEX + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S")
        shutil.copy2(INDEX, backup)
        with open(INDEX, "w", encoding="utf-8") as fh:
            json.dump(data, fh, ensure_ascii=False, indent=2)
        print(f"+ {nuevos} modelos añadidos. Total fragmentos: {len(frags)}. Backup: {backup}")
    else:
        print("Sin cambios: todos los modelos ya existían.")


if __name__ == "__main__":
    main()
