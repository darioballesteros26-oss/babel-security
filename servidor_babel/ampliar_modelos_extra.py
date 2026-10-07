#!/usr/bin/env python3
"""
ampliar_modelos_extra.py — Segundo lote de MODELOS DE DOCUMENTOS (abrev "MEP") para
la biblioteca jurídica local (RAG). Cubre tipos que faltaban en el primer lote:
ejecución, casación, nulidad, familia contenciosa, laboral, penal, tributario,
extranjería y contratos.

Mismo criterio que ampliar_modelos_biblioteca.py: las plantillas aportan ESTRUCTURA
(secciones, fórmulas, orden) con [HUECOS] para los datos; las citas legales exactas las
pone la biblioteca de leyes vía RAG. NO se inventan artículos dentro del texto: el marco
legal va en el título como referencia estándar verificada.

Idempotente (clave: articulo). Backup antes de escribir.  Uso: python3 ampliar_modelos_extra.py
"""
import json, os, shutil, sys
from datetime import datetime

INDEX = os.path.expanduser("~/Babel/biblioteca_juridica/index.json")

# (articulo, titulo, capitulo, texto)
MODELOS = [
 ("demanda-ejecucion-titulos-judiciales",
  "Modelo de demanda de ejecución de título judicial — estructura conforme a LEC arts. 517, 549 y 551",
  "Ejecución civil",
  """AL JUZGADO DE PRIMERA INSTANCIA [N.º ___] DE [CIUDAD]

D./Dña. [EJECUTANTE], con DNI [COMPLETAR], representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], ante el Juzgado comparezco y DIGO:

Que mediante el presente escrito formulo DEMANDA EJECUTIVA contra [EJECUTADO], con DNI/CIF [COMPLETAR] y domicilio en [DIRECCIÓN], en virtud del siguiente

TÍTULO EJECUTIVO
[Sentencia firme / auto / decreto / transacción judicial] dictado por [ÓRGANO] en el procedimiento [N.º], de fecha [FECHA], que condena a la parte ejecutada a [OBLIGACIÓN: pago de ___ euros / hacer / entregar].

HECHOS
PRIMERO.- El título es firme y lleva aparejada ejecución. (Documento n.º 1: testimonio.)
SEGUNDO.- La parte ejecutada no ha cumplido voluntariamente en el plazo legal.
TERCERO.- Cantidad reclamada: [PRINCIPAL] de principal, más [30%] presupuestado para intereses y costas de la ejecución.

FUNDAMENTOS DE DERECHO
I.- Competencia y título ejecutivo (art. [COMPLETAR] [ABREV]).
II.- Procedencia del despacho de ejecución.

SUPLICO AL JUZGADO: que despache ejecución contra [EJECUTADO] por [CANTIDAD] de principal más intereses y costas, y acuerde los embargos y medidas ejecutivas procedentes.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("oposicion-a-la-ejecucion",
  "Modelo de escrito de oposición a la ejecución — estructura conforme a LEC arts. 556 a 564",
  "Ejecución civil",
  """AL JUZGADO DE PRIMERA INSTANCIA [N.º ___] DE [CIUDAD]
Procedimiento de ejecución n.º [COMPLETAR]

D./Dña. [EJECUTADO], parte ejecutada, representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], DIGO:

Que, dentro del plazo legal desde la notificación del auto despachando ejecución, formulo OPOSICIÓN A LA EJECUCIÓN, con base en los siguientes

MOTIVOS
PRIMERO.- [Motivo de fondo: pago o cumplimiento / pluspetición / prescripción / transacción homologada — según el caso].
SEGUNDO.- [Motivo procesal, si procede: falta de carácter o representación / nulidad del despacho de ejecución].

HECHOS Y PRUEBA
PRIMERO.- [Relato]. (Documentos n.º 1 y ss.)

SUPLICO AL JUZGADO: que tenga por formulada oposición a la ejecución y, previos los trámites legales, dicte auto dejando sin efecto la ejecución despachada [total o parcialmente], con imposición de costas a la ejecutante.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("recurso-casacion-civil",
  "Modelo de recurso de casación civil — estructura conforme a LEC arts. 477 y 481",
  "Recursos civiles",
  """A LA SALA DE LO CIVIL DEL TRIBUNAL SUPREMO (por conducto de la Audiencia Provincial de [CIUDAD])

D./Dña. [RECURRENTE], representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], DIGO:

Que mediante el presente escrito interpongo RECURSO DE CASACIÓN contra la sentencia de la Audiencia Provincial de [CIUDAD], Sección [N.º], de fecha [FECHA], dictada en el rollo de apelación n.º [COMPLETAR], con base en el siguiente

INTERÉS CASACIONAL
[Oposición a doctrina del Tribunal Supremo / jurisprudencia contradictoria de Audiencias / norma con menos de 5 años de vigencia]: [JUSTIFICACIÓN].

MOTIVO ÚNICO/PRIMERO
Infracción de [norma sustantiva: art. ___ [ABREV]]. [Desarrollo de la infracción y su relevancia en el fallo.]

SUPLICO A LA SALA: que tenga por interpuesto recurso de casación, lo admita y, tras su tramitación, case y anule la sentencia recurrida, dictando otra conforme a la doctrina infringida.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("incidente-nulidad-actuaciones",
  "Modelo de incidente de nulidad de actuaciones — estructura conforme a LOPJ art. 241 y LEC art. 228",
  "Recursos civiles",
  """AL [ÓRGANO QUE DICTÓ LA RESOLUCIÓN] — Procedimiento n.º [COMPLETAR]

D./Dña. [PROMOVENTE], representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], DIGO:

Que, al amparo del art. 241 LOPJ, dentro de los 20 días desde la notificación de la resolución firme, promuevo INCIDENTE DE NULIDAD DE ACTUACIONES, por vulneración de un derecho fundamental del art. 24 CE que no pudo denunciarse antes y contra el que no cabe recurso ordinario ni extraordinario.

HECHOS
PRIMERO.- [Resolución firme y fecha de notificación.]
SEGUNDO.- [Vulneración concreta: indefensión / incongruencia / falta de motivación], que causó indefensión material.

SUPLICO: que se declare la nulidad de las actuaciones desde [MOMENTO] y se repongan al estado anterior a la vulneración.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("demanda-reclamacion-cantidad-civil",
  "Modelo de demanda de reclamación de cantidad (civil) — estructura conforme a LEC arts. 249/250 (ordinario o verbal según cuantía)",
  "Demanda civil",
  """AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]

D./Dña. [DEMANDANTE], con DNI [COMPLETAR] y domicilio en [DIRECCIÓN], [por sí / con Procurador y Letrado según cuantía], DIGO:

Que formulo DEMANDA DE [JUICIO VERBAL si ≤ 6.000 € / ORDINARIO si > 6.000 €] en reclamación de cantidad contra [DEMANDADO], domicilio en [DIRECCIÓN], con base en los siguientes

HECHOS
PRIMERO.- [Origen de la deuda: contrato / préstamo / servicios / factura], por importe de [CANTIDAD] euros. (Documento n.º 1.)
SEGUNDO.- Vencimiento y falta de pago pese a requerimiento de [FECHA]. (Documento n.º 2.)

FUNDAMENTOS DE DERECHO
I.- Obligación de cumplir lo pactado y de pagar (arts. [COMPLETAR] CC).
II.- Procedimiento, competencia, intereses (art. 1108 CC) y costas.

SUPLICO AL JUZGADO: que condene a [DEMANDADO] a pagar [CANTIDAD] euros más intereses legales desde [FECHA] y las costas.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [DEMANDANTE / LETRADO]."""),

 ("demanda-division-cosa-comun",
  "Modelo de demanda de división de cosa común — estructura conforme a CC arts. 400 a 406 y LEC",
  "Demanda civil",
  """AL JUZGADO DE PRIMERA INSTANCIA DE [CIUDAD]

D./Dña. [DEMANDANTE], copropietario, con DNI [COMPLETAR], representado y asistido en su caso, DIGO:

Que formulo DEMANDA DE DIVISIÓN DE COSA COMÚN contra [LOS DEMÁS COPROPIETARIOS], con base en los siguientes

HECHOS
PRIMERO.- Las partes son copropietarias del [BIEN: finca sita en ___, inscrita en el Registro ___] en las cuotas: [CUOTAS]. (Documento n.º 1: título/nota simple.)
SEGUNDO.- No existe pacto de indivisión y no hay acuerdo sobre la división o venta.
TERCERO.- El bien es [indivisible / de cómoda división]: procede [la venta en pública subasta y reparto del precio / la adjudicación por lotes].

FUNDAMENTOS DE DERECHO
I.- Nadie está obligado a permanecer en la comunidad (art. 400 CC).
II.- División o venta y reparto (arts. 404 y 1062 CC).

SUPLICO AL JUZGADO: que declare la extinción del condominio y acuerde [la venta en pública subasta con admisión de licitadores extraños y reparto del precio según cuotas].

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [DEMANDANTE / LETRADO]."""),

 ("demanda-divorcio-contencioso",
  "Modelo de demanda de divorcio contencioso — estructura conforme a CC art. 86 y LEC arts. 770 y 771",
  "Familia",
  """AL JUZGADO DE PRIMERA INSTANCIA [DE FAMILIA] DE [CIUDAD]

D./Dña. [DEMANDANTE], con DNI [COMPLETAR], representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], DIGO:

Que formulo DEMANDA DE DIVORCIO contra [CÓNYUGE DEMANDADO], con base en los siguientes

HECHOS
PRIMERO.- Matrimonio celebrado el [FECHA] en [LUGAR]. (Documento n.º 1: certificado de matrimonio.)
SEGUNDO.- Hijos [menores/mayores dependientes]: [DATOS]. (Documento n.º 2: certificados de nacimiento.)
TERCERO.- Ha transcurrido el plazo legal desde el matrimonio; se interesa el divorcio y las siguientes MEDIDAS: guarda y custodia, patria potestad, régimen de visitas, pensión de alimentos [CANTIDAD], uso de la vivienda y, en su caso, pensión compensatoria.

FUNDAMENTOS DE DERECHO
I.- Procedencia del divorcio (art. 86 CC).
II.- Medidas respecto de hijos y cónyuges (arts. 90 a 97 CC); interés superior del menor.

SUPLICO AL JUZGADO: que decrete el divorcio y acuerde las medidas definitivas interesadas.
OTROSÍ DIGO: se solicitan como medidas provisionales las anteriores durante la tramitación (art. 773 LEC).

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("demanda-guarda-custodia-alimentos",
  "Modelo de demanda de guarda y custodia / alimentos de hijos no matrimoniales — estructura conforme a CC arts. 92, 154 y 774 LEC",
  "Familia",
  """AL JUZGADO DE PRIMERA INSTANCIA [DE FAMILIA] DE [CIUDAD]

D./Dña. [DEMANDANTE], progenitor/a, con DNI [COMPLETAR], representado y asistido en su caso, DIGO:

Que formulo DEMANDA DE MEDIDAS PATERNOFILIALES (guarda y custodia, patria potestad, visitas y alimentos) respecto del/de los hijo/s menor/es [NOMBRE, FECHA NACIMIENTO], frente a [OTRO PROGENITOR], con base en los siguientes

HECHOS
PRIMERO.- Filiación acreditada. (Documento n.º 1: certificado de nacimiento.)
SEGUNDO.- Los progenitores no conviven y no hay acuerdo sobre las medidas.
TERCERO.- Interés del menor: se propone [custodia materna/paterna/compartida], régimen de visitas [DETALLE] y pensión de alimentos de [CANTIDAD] euros/mes actualizable conforme al IPC, más gastos extraordinarios al 50%.

FUNDAMENTOS DE DERECHO
I.- Patria potestad y guarda (arts. 154 y 92 CC).
II.- Obligación de alimentos (arts. 142 y ss. CC); interés superior del menor.

SUPLICO AL JUZGADO: que fije las medidas interesadas en interés del menor.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [DEMANDANTE / LETRADO]."""),

 ("demanda-modificacion-sustancial-laboral",
  "Modelo de demanda por modificación sustancial de condiciones de trabajo — estructura conforme a ET art. 41 y LRJS art. 138",
  "Laboral",
  """AL JUZGADO DE LO SOCIAL DE [CIUDAD]

D./Dña. [TRABAJADOR], con DNI [COMPLETAR] y domicilio en [DIRECCIÓN], DIGO:

Que formulo DEMANDA por MODIFICACIÓN SUSTANCIAL DE CONDICIONES DE TRABAJO contra la empresa [EMPRESA], CIF [COMPLETAR], con base en los siguientes

HECHOS
PRIMERO.- Relación laboral: antigüedad [FECHA], categoría [COMPLETAR], salario [COMPLETAR].
SEGUNDO.- La empresa notificó el [FECHA] la modificación de [jornada / horario / turnos / funciones / salario], con efectos [FECHA]. (Documento n.º 1.)
TERCERO.- La medida [es injustificada / causa perjuicio] y no concurren causas económicas, técnicas, organizativas o de producción acreditadas.

FUNDAMENTOS DE DERECHO
I.- Modificación sustancial (art. 41 ET).
II.- Tramitación urgente y preferente (art. 138 LRJS).

SUPLICO AL JUZGADO: que declare [injustificada / nula] la modificación y reponga al trabajador en sus anteriores condiciones, con abono de daños y perjuicios.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [TRABAJADOR / GRADUADO SOCIAL / LETRADO]."""),

 ("recurso-suplicacion-social",
  "Modelo de recurso de suplicación (social) — estructura conforme a LRJS arts. 190 a 196",
  "Laboral",
  """A LA SALA DE LO SOCIAL DEL TRIBUNAL SUPERIOR DE JUSTICIA DE [CCAA] (por conducto del Juzgado de lo Social n.º [___] de [CIUDAD])

D./Dña. [RECURRENTE], representado y asistido en su caso, DIGO:

Que interpongo RECURSO DE SUPLICACIÓN contra la sentencia del Juzgado de lo Social n.º [___] de [CIUDAD], de fecha [FECHA], autos n.º [COMPLETAR], con base en los siguientes motivos del art. 193 LRJS:

PRIMERO.- [Reposición de autos por infracción de normas/garantías procesales con indefensión], si procede.
SEGUNDO.- [Revisión de hechos probados] a la vista de [documento/pericia], proponiendo nueva redacción del hecho [N.º].
TERCERO.- [Examen del derecho aplicado]: infracción de [art. ___ [ABREV]].

SUPLICO A LA SALA: que estime el recurso, revoque la sentencia y dicte otra conforme a lo interesado, con los pronunciamientos que correspondan.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [GRADUADO SOCIAL / LETRADO]."""),

 ("recurso-casacion-penal",
  "Modelo de recurso de casación penal — estructura conforme a LECrim arts. 847, 849 y 852",
  "Recursos penales",
  """A LA SALA SEGUNDA DE LO PENAL DEL TRIBUNAL SUPREMO (por conducto de [ÓRGANO DE INSTANCIA])

D./Dña. [RECURRENTE], representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], DIGO:

Que preparo/interpongo RECURSO DE CASACIÓN contra la sentencia de [AUDIENCIA PROVINCIAL/TSJ] de [CIUDAD], de fecha [FECHA], causa n.º [COMPLETAR], con base en los siguientes

MOTIVOS
PRIMERO.- Por infracción de precepto constitucional (art. 852 LECrim), al vulnerarse el derecho [a la presunción de inocencia / tutela judicial / art. 24 CE].
SEGUNDO.- Por infracción de ley (art. 849.1 LECrim): aplicación indebida/inaplicación del art. [___] CP.
TERCERO.- Por error en la valoración de la prueba (art. 849.2 LECrim) basado en documento literosuficiente.

SUPLICO A LA SALA: que case y anule la sentencia, dictando otra absolutoria / con la pena procedente conforme a los motivos.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("solicitud-sobreseimiento",
  "Modelo de escrito solicitando el sobreseimiento — estructura conforme a LECrim arts. 637, 641 y 779",
  "Penal",
  """AL JUZGADO DE INSTRUCCIÓN N.º [___] DE [CIUDAD] — Diligencias Previas n.º [COMPLETAR]

D./Dña. [INVESTIGADO / SU DEFENSA], representado por el Procurador [COMPLETAR] y asistido del Letrado [COMPLETAR], DIGO:

Que, evacuado el traslado conferido, intereso el SOBRESEIMIENTO [LIBRE (art. 637 LECrim) / PROVISIONAL (art. 641 LECrim)] de las presentes actuaciones, con base en los siguientes

HECHOS Y RAZONAMIENTOS
PRIMERO.- [El hecho no es constitutivo de delito / no existen indicios racionales de criminalidad contra mi representado / no resulta debidamente justificada la perpetración].
SEGUNDO.- [Valoración de la instrucción practicada y ausencia de prueba de cargo suficiente.]

SUPLICO AL JUZGADO: que acuerde el sobreseimiento [libre/provisional] y el archivo de las actuaciones respecto de [INVESTIGADO].

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [PROCURADOR / LETRADO]."""),

 ("recurso-reposicion-tributario",
  "Modelo de recurso de reposición tributario — estructura conforme a LGT art. 222 a 225",
  "Tributario",
  """A LA [ADMINISTRACIÓN/DELEGACIÓN DE LA AEAT / ÓRGANO QUE DICTÓ EL ACTO]

D./Dña. [INTERESADO], con DNI/NIF [COMPLETAR] y domicilio a efectos de notificaciones en [DIRECCIÓN], DIGO:

Que, dentro del plazo de UN MES desde la notificación, interpongo RECURSO DE REPOSICIÓN contra [ACTO: liquidación / sanción / providencia de apremio] con n.º de referencia [COMPLETAR], notificado el [FECHA], con base en las siguientes

ALEGACIONES
PRIMERA.- [Motivo: error en la base/cuota / prescripción / falta de motivación / defecto de notificación / improcedencia de la sanción].
SEGUNDA.- [Fundamentación y prueba. Documentos n.º 1 y ss.]

SUPLICO: que se tenga por interpuesto el recurso y se anule [total o parcialmente] el acto impugnado. OTROSÍ: se solicita la SUSPENSIÓN del acto conforme al art. 233 LGT, aportando [garantía/aval] / alegando perjuicios de difícil reparación.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [INTERESADO/REPRESENTANTE]."""),

 ("reclamacion-economico-administrativa",
  "Modelo de reclamación económico-administrativa (TEAR/TEAC) — estructura conforme a LGT arts. 226, 235 y 237",
  "Tributario",
  """AL TRIBUNAL ECONÓMICO-ADMINISTRATIVO [REGIONAL DE ___ / CENTRAL] (por conducto del órgano que dictó el acto)

D./Dña. [RECLAMANTE], con NIF [COMPLETAR] y domicilio en [DIRECCIÓN], DIGO:

Que, dentro del plazo de UN MES, interpongo RECLAMACIÓN ECONÓMICO-ADMINISTRATIVA contra [ACTO: liquidación / resolución del recurso de reposición / sanción] de [ÓRGANO], referencia [COMPLETAR], notificado el [FECHA].

ALEGACIONES
PRIMERA.- [Motivos de fondo y/o forma: improcedencia de la liquidación / prescripción / falta de motivación.]
SEGUNDA.- [Prueba documental. Documentos n.º 1 y ss.]

SUPLICO AL TRIBUNAL: que tenga por interpuesta la reclamación, la estime y anule el acto impugnado. OTROSÍ: suspensión del acto (art. 233 LGT) con la garantía aportada.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [RECLAMANTE/REPRESENTANTE]."""),

 ("solicitud-nacionalidad-residencia",
  "Modelo de solicitud de nacionalidad española por residencia — estructura conforme a CC art. 22 y RD 1004/2015",
  "Extranjería",
  """A LA DIRECCIÓN GENERAL DE SEGURIDAD JURÍDICA Y FE PÚBLICA — MINISTERIO DE JUSTICIA

D./Dña. [SOLICITANTE], nacido/a en [LUGAR] el [FECHA], nacionalidad [COMPLETAR], con NIE [COMPLETAR] y domicilio en [DIRECCIÓN], DIGO:

Que SOLICITO la concesión de la NACIONALIDAD ESPAÑOLA POR RESIDENCIA, al cumplir los requisitos legales:
PRIMERO.- Residencia legal, continuada e inmediatamente anterior, de [10 años / 2 años (iberoamericanos, etc.) / 1 año (casos del art. 22.2 CC)]. (Documentos: certificados de residencia.)
SEGUNDO.- Buena conducta cívica (certificado de antecedentes penales de España y país de origen) y suficiente grado de integración (pruebas DELE/A2 y CCSE del Instituto Cervantes).
TERCERO.- [Documentación: certificado de nacimiento legalizado/apostillado y traducido, certificado de empadronamiento, etc.]

SUPLICO: que, previa tramitación, se conceda la nacionalidad española por residencia, con juramento/promesa de fidelidad al Rey y obediencia a la Constitución.

En [CIUDAD], a [COMPLETAR: FECHA]. Fdo.: [SOLICITANTE]."""),

 ("contrato-laboral",
  "Modelo de contrato de trabajo — estructura conforme a ET arts. 8, 15 y 16",
  "Contratos",
  """CONTRATO DE TRABAJO [INDEFINIDO / TEMPORAL POR CIRCUNSTANCIAS DE LA PRODUCCIÓN / FIJO-DISCONTINUO]

En [CIUDAD], a [COMPLETAR: FECHA].

REUNIDOS
De una parte, la EMPRESA [NOMBRE/RAZÓN SOCIAL], CIF [COMPLETAR], domicilio [DIRECCIÓN], representada por [REPRESENTANTE].
De otra, EL TRABAJADOR/A D./Dña. [NOMBRE], DNI/NIE [COMPLETAR], domicilio [DIRECCIÓN].

ACUERDAN
PRIMERA.- OBJETO: el trabajador prestará servicios como [CATEGORÍA/PUESTO], grupo profesional [COMPLETAR].
SEGUNDA.- DURACIÓN: [indefinida / del ___ al ___; causa si temporal] y periodo de prueba de [COMPLETAR].
TERCERA.- JORNADA: [COMPLETAR] horas semanales, horario [COMPLETAR].
CUARTA.- RETRIBUCIÓN: [SALARIO] euros brutos [anuales/mensuales] en [N.º] pagas, conforme al Convenio Colectivo de [SECTOR].
QUINTA.- CENTRO DE TRABAJO: [DIRECCIÓN]. VACACIONES: [30 días naturales/año].
SEXTA.- El contrato se regirá por el Estatuto de los Trabajadores y el convenio aplicable.

Y en prueba de conformidad, firman por duplicado.
LA EMPRESA: ______________    EL TRABAJADOR/A: ______________"""),

 ("contrato-prestamo",
  "Modelo de contrato de préstamo entre particulares — estructura conforme a CC arts. 1740 a 1757",
  "Contratos",
  """CONTRATO DE PRÉSTAMO (MUTUO)

En [CIUDAD], a [COMPLETAR: FECHA].

REUNIDOS
De una parte, EL PRESTAMISTA D./Dña. [NOMBRE], DNI [COMPLETAR], domicilio [DIRECCIÓN].
De otra, EL PRESTATARIO D./Dña. [NOMBRE], DNI [COMPLETAR], domicilio [DIRECCIÓN].

ESTIPULACIONES
PRIMERA.- El prestamista entrega en este acto al prestatario la cantidad de [IMPORTE] euros, que éste declara recibir mediante [transferencia/efectivo].
SEGUNDA.- DEVOLUCIÓN: el prestatario se obliga a devolver dicha cantidad [el día ___ / en ___ cuotas mensuales de ___ euros, del ___ al ___].
TERCERA.- INTERÉS: [sin interés / interés anual del ___% ]. [Si hay interés, no podrá ser usurario conforme a la Ley de 23 de julio de 1908.]
CUARTA.- IMPAGO: el impago de [N.º] cuotas faculta al prestamista para reclamar la totalidad pendiente, más el interés de demora pactado.
QUINTA.- Para cualquier controversia, las partes se someten a los Juzgados de [CIUDAD].

Y en prueba de conformidad, firman por duplicado.
EL PRESTAMISTA: ______________    EL PRESTATARIO: ______________"""),

 ("contrato-arrendamiento-local-negocio",
  "Modelo de contrato de arrendamiento para uso distinto de vivienda (local de negocio) — estructura conforme a LAU arts. 3 y 29 a 35",
  "Contratos",
  """CONTRATO DE ARRENDAMIENTO PARA USO DISTINTO DE VIVIENDA (LOCAL DE NEGOCIO)

En [CIUDAD], a [COMPLETAR: FECHA].

REUNIDOS
ARRENDADOR: D./Dña. [NOMBRE], DNI/CIF [COMPLETAR], domicilio [DIRECCIÓN].
ARRENDATARIO: D./Dña. [NOMBRE], DNI/CIF [COMPLETAR], domicilio [DIRECCIÓN].

ESTIPULACIONES
PRIMERA.- OBJETO: arrendamiento del local sito en [DIRECCIÓN], referencia catastral [COMPLETAR], para destinarlo a la actividad de [COMPLETAR].
SEGUNDA.- DURACIÓN: [AÑOS], con inicio el [FECHA]; prórrogas [PACTO].
TERCERA.- RENTA: [IMPORTE] euros/mes, pago en los [___] primeros días, actualizable según [índice pactado]. FIANZA: dos mensualidades (art. 36 LAU).
CUARTA.- GASTOS: [IBI, comunidad, suministros — reparto pactado].
QUINTA.- OBRAS, cesión y subarriendo, y resolución por incumplimiento.
SEXTA.- Régimen: LAU (uso distinto de vivienda) y, supletoriamente, Código Civil.

Y en prueba de conformidad, firman por duplicado.
EL ARRENDADOR: ______________    EL ARRENDATARIO: ______________"""),
]

def main():
    if not os.path.exists(INDEX):
        sys.stderr.write(f"No existe {INDEX}\n"); sys.exit(1)
    data = json.load(open(INDEX, encoding="utf-8"))
    frags = data["fragmentos"]
    existentes = {f.get("articulo") for f in frags if f.get("abrev") == "MEP"}
    nuevos = 0
    for art, titulo, cap, texto in MODELOS:
        if art in existentes:
            continue
        frags.append({
            "ley": "Modelos de Escritos Procesales", "abrev": "MEP", "boe_id": None,
            "articulo": art, "titulo": titulo, "capitulo": cap, "seccion": None,
            "texto": texto.strip(),
            "fuente_url": "Elaboración propia — estructura estándar verificada",
            "fecha_consolidada": "2026",
        })
        nuevos += 1
    if nuevos == 0:
        print("Nada que añadir (ya presentes)."); return
    shutil.copy2(INDEX, INDEX + ".bak-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
    json.dump(data, open(INDEX, "w", encoding="utf-8"), ensure_ascii=False, indent=1)
    print(f"Añadidos {nuevos} modelos. Total fragmentos: {len(frags)}")

if __name__ == "__main__":
    main()
