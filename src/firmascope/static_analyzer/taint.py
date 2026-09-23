"""Seguimiento de procedencia sobre el AST (source -> transform -> sink).

El analisis es intraprocedural con propagacion interprocedural por punto fijo:

1. se recogen todas las funciones del script y se construye el grafo de llamadas;
2. dentro de cada funcion se propagan etiquetas por asignaciones, expresiones,
   miembros, literales y transformaciones conocidas;
3. los argumentos etiquetados de una llamada siembran los parametros de la
   funcion destino, y el valor de retorno vuelve al llamante;
4. se itera hasta que no cambia nada (o se agota el limite de iteraciones).

Es deliberadamente aproximado. JavaScript no permite un seguimiento perfecto de
procedencia, asi que cada ruta encontrada lleva una confianza explicita y el
motor de reglas la reporta como ``POTENTIAL``, nunca como hecho observado.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable

from ..audit_core.conclusions import Confidence
from ..audit_core.events import PRIVATE_TAGS, Tag
from . import catalog, parser
from .catalog import CallPattern

#: Iteraciones maximas del punto fijo interprocedural.
MAX_ITERATIONS = 8

#: Profundidad maxima de la cadena de llamadas reconstruida para el reporte.
MAX_CALL_CHAIN = 5

PRIVATE_LABELS = frozenset(t.value for t in PRIVATE_TAGS)

#: Prefijo de los marcadores simbolicos de parametro: ``@<funcion>:<posicion>``,
#: con sufijo ``|pub`` si solo deben sustituirse etiquetas publicas (tras
#: atravesar una firma). Nunca salen de este modulo.
MARKER = "@"
PUBLIC_SUFFIX = "|pub"


def _is_marker(label: str) -> bool:
    return label.startswith(MARKER)


def _dom_hint_only(value: "TaintValue") -> bool:
    """True si la procedencia es solo la pista del selector de un elemento."""
    return not value.empty and value.origin is not None and value.origin.kind == "dom"


#: Nodos que abren un ambito de bloque para ``let``/``const``.
BLOCK_TYPES = frozenset({"statement_block", "for_statement", "for_in_statement",
                         "switch_case", "switch_default", "class_body"})


# ----------------------------------------------------------------------
# Valores de taint
# ----------------------------------------------------------------------

@dataclass(frozen=True)
class SourceRef:
    """Punto de entrada del material sensible."""

    name: str        # "FileReader.readAsArrayBuffer" o "identificador: keyBytes"
    kind: str        # "api" (patron reconocido) o "name" (heuristica de nombre)
    line: int
    snippet: str

    def to_dict(self) -> dict[str, Any]:
        return {"name": self.name, "kind": self.kind, "line": self.line, "snippet": self.snippet}


@dataclass(frozen=True)
class TaintValue:
    """Etiquetas de procedencia de una expresion, con su trazabilidad."""

    labels: frozenset[str] = frozenset()
    origin: SourceRef | None = None
    hops: int = 0                       # saltos entre funciones
    transforms: tuple[str, ...] = ()
    derived: bool = False

    @property
    def empty(self) -> bool:
        return not self.labels

    @property
    def private(self) -> bool:
        return bool(self.labels & PRIVATE_LABELS)

    def merge(self, other: "TaintValue") -> "TaintValue":
        if other.empty:
            return self
        if self.empty:
            return other
        return TaintValue(
            labels=self.labels | other.labels,
            origin=_best_origin(self.origin, other.origin),
            hops=min(self.hops, other.hops),
            transforms=_merge_transforms(self.transforms, other.transforms),
            derived=self.derived or other.derived,
        )

    def through(self, transform: str, derived: bool = True) -> "TaintValue":
        """Propaga el valor a traves de una transformacion."""
        if self.empty:
            return self
        return TaintValue(
            labels=self.labels,
            origin=self.origin,
            hops=self.hops,
            transforms=_merge_transforms(self.transforms, (transform,)),
            derived=self.derived or derived,
        )

    def across_call(self) -> "TaintValue":
        """Propaga el valor cruzando una frontera de funcion."""
        if self.empty:
            return self
        return TaintValue(self.labels, self.origin, self.hops + 1, self.transforms, self.derived)

    def with_labels(self, labels: Iterable[str]) -> "TaintValue":
        extra = frozenset(labels)
        if not extra:
            return self
        return TaintValue(self.labels | extra, self.origin, self.hops, self.transforms, self.derived)

    def confidence(self) -> Confidence:
        """Confianza derivada del tipo de origen y del numero de saltos."""
        if self.origin is None:
            return Confidence.LOW
        if self.origin.kind in ("name", "dom"):
            return Confidence.LOW
        if self.hops == 0 and len(self.transforms) <= 2:
            return Confidence.HIGH
        if self.hops <= 2:
            return Confidence.MEDIUM
        return Confidence.LOW


EMPTY = TaintValue()


def _best_origin(a: SourceRef | None, b: SourceRef | None) -> SourceRef | None:
    if a is None:
        return b
    if b is None:
        return a
    if a.kind == b.kind:
        return a
    return a if a.kind == "api" else b


def _merge_transforms(a: tuple[str, ...], b: tuple[str, ...]) -> tuple[str, ...]:
    out: list[str] = list(a)
    for item in b:
        if item not in out:
            out.append(item)
    return tuple(out[:8])


# ----------------------------------------------------------------------
# Estructuras del analisis
# ----------------------------------------------------------------------

@dataclass
class FunctionInfo:
    """Una funcion del script (incluye el modulo como funcion sintetica)."""

    name: str
    node: Any
    params: list[str]
    line: int
    parent: "FunctionInfo | None" = None
    is_module: bool = False
    #: True si la funcion es el ejecutor de ``new Promise(...)``.
    is_promise_executor: bool = False

    variables: dict[str, TaintValue] = field(default_factory=dict)
    param_taint: dict[str, TaintValue] = field(default_factory=dict)
    #: Nombres declarados en este ambito, para resolver la cadena de ambitos.
    declared: set[str] = field(default_factory=set)
    returns: TaintValue = EMPTY
    calls: list["CallSite"] = field(default_factory=list)
    sinks: list["SinkSite"] = field(default_factory=list)

    @property
    def start(self) -> int:
        return self.node.start_byte

    @property
    def end(self) -> int:
        return self.node.end_byte

    def label(self) -> str:
        return self.name if self.name else "(anonima)"


@dataclass
class CallSite:
    callee: str
    node: Any
    args: list[Any]
    caller: FunctionInfo
    line: int
    #: Funcion local resuelta por ambito lexico.
    target: "FunctionInfo | None" = None


@dataclass
class ParamCall:
    """Llamada a traves de un parametro: ``function run(cb) { cb(x) }``."""

    param: str
    args: list[Any]
    #: Funcion donde ocurre la llamada: los argumentos se evaluan en ella, que
    #: puede ser una funcion anidada que captura el parametro por clausura.
    evaluator: "FunctionInfo"


@dataclass
class SinkSite:
    pattern: CallPattern
    node: Any
    data_nodes: list[Any]
    url_node: Any | None
    function: FunctionInfo
    line: int
    snippet: str


@dataclass
class StaticPath:
    """Ruta source -> transform -> sink encontrada en el codigo."""

    source: SourceRef
    sink_name: str
    sink_snippet: str
    sink_line: int
    channel: str
    labels: list[str]
    transforms: list[str]
    confidence: Confidence
    call_chain: list[str]
    file_label: str
    url: str
    hops: int
    derived: bool

    @property
    def private(self) -> bool:
        return bool(set(self.labels) & PRIVATE_LABELS)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source.to_dict(),
            "sink": self.sink_name,
            "sink_snippet": self.sink_snippet,
            "sink_line": self.sink_line,
            "channel": self.channel,
            "labels": list(self.labels),
            "transforms": list(self.transforms),
            "confidence": self.confidence.value,
            "call_chain": list(self.call_chain),
            "file": self.file_label,
            "url": self.url,
            "hops": self.hops,
            "derived": self.derived,
            "private": self.private,
        }


# ----------------------------------------------------------------------
# Analisis de un script
# ----------------------------------------------------------------------

class ScriptAnalysis:
    """Analiza un unico script y devuelve las rutas sensibles encontradas."""

    def __init__(self, source: bytes, file_label: str, url: str = "",
                 symbolic: bool = False, tree: Any = None):
        self.source = source
        self.file_label = file_label
        self.url = url
        self.tree = tree if tree is not None else parser.parse(source)
        #: Modo simbolico: resume cada funcion con marcadores en sus
        #: parametros, sin procedencia de ningun llamante concreto.
        self.symbolic = symbolic
        #: Resumenes simbolicos por indice de funcion (solo en modo real).
        self.summaries: dict[int, TaintValue] = {}
        self._index: dict[int, int] = {}
        self.functions: list[FunctionInfo] = []
        self.by_name: dict[str, FunctionInfo] = {}
        self.call_edges: dict[str, set[str]] = {}
        #: (ambito, nombre) -> funcion declarada directamente en ese ambito.
        self.scoped: dict[tuple[int, str], FunctionInfo] = {}
        #: (inicio, fin) -> funcion, para localizar funciones literales pasadas
        #: como argumento.
        self.by_span: dict[tuple[int, int], FunctionInfo] = {}
        #: id(funcion duena del parametro) -> {nodo: llamada}. Se reconstruye
        #: en cada iteracion del punto fijo.
        self.param_calls: dict[int, dict[tuple, ParamCall]] = {}
        #: (inicio, fin) de un bloque anidado -> nombres let/const declarados en
        #: el. El codigo minificado reutiliza nombres en bloques hermanos
        #: (`const t` fuera y `const t` dentro de un try); sin distinguirlos, el
        #: .cer heredaria la procedencia del .key.
        self.block_decls: dict[tuple[int, int], set[str]] = {}
        self.paths: list[StaticPath] = []
        #: Marca de cambio del punto fijo. Una asignacion puede alcanzar el
        #: ambito de otra funcion, asi que la convergencia no puede deducirse
        #: unicamente del estado de la funcion que se esta analizando.
        self._changed = False

    # -- API ------------------------------------------------------------
    def run(self) -> list[StaticPath]:
        if self.tree is None:
            return []
        self._collect_functions()
        # Primero, los resumenes: que devuelve cada funcion por si misma y que
        # parametros deja pasar hasta su retorno. Sin ellos, una funcion
        # llamada con el .key y luego con el .cer mezclaria ambos en un unico
        # retorno, y el certificado — que viaja junto a la firma — arrastraria
        # la procedencia de la clave: un falso positivo sobre el envio que todo
        # sitio correcto hace.
        summary = ScriptAnalysis(self.source, self.file_label, self.url,
                                 symbolic=True, tree=self.tree)
        summary.summarize()
        self.summaries = {i: fn.returns for i, fn in enumerate(summary.functions)}
        self._fixpoint()
        self._collect_paths()
        return self.paths

    def summarize(self) -> None:
        """Solo el punto fijo simbolico (lo invoca el analisis real)."""
        if self.tree is None:
            return
        self._collect_functions()
        self._fixpoint()

    # -- recoleccion de funciones ---------------------------------------
    def _collect_block_declarations(self) -> None:
        for node in parser.walk(self.tree.root_node):
            if node.type not in ("lexical_declaration", "class_declaration"):
                continue
            block = node.parent
            while block is not None and block.type not in BLOCK_TYPES and block.type != "program" \
                    and block.type not in parser.FUNCTION_TYPES:
                block = block.parent
            # El cuerpo de una funcion y el programa son el ambito de la
            # funcion: ahi los nombres se guardan tal cual, como hasta ahora.
            if block is None or block.type not in BLOCK_TYPES:
                continue
            if block.type == "statement_block" and block.parent is not None \
                    and block.parent.type in parser.FUNCTION_TYPES:
                continue
            names = self.block_decls.setdefault((block.start_byte, block.end_byte), set())
            if node.type == "class_declaration":
                name = parser.field(node, "name")
                if name is not None:
                    names.add(parser.text(name, self.source))
                continue
            for declarator in node.named_children:
                if declarator.type != "variable_declarator":
                    continue
                target = parser.field(declarator, "name")
                if target is None:
                    continue
                if target.type == "identifier":
                    names.add(parser.text(target, self.source))
                else:
                    for leaf in parser.walk(target):
                        if leaf.type in ("identifier", "shorthand_property_identifier_pattern"):
                            names.add(parser.text(leaf, self.source))

    def _bind(self, name: str, node: Any, fn: FunctionInfo) -> str:
        """Clave de ``name`` visto desde ``node`` dentro de ``fn``.

        Si un bloque anidado entre ``node`` y ``fn`` declara ``name`` con
        let/const, la clave lleva ese bloque; si no, es el nombre sin mas.
        """
        if not self.block_decls or node is None:
            return name
        current = node.parent
        while current is not None:
            if current.start_byte == fn.start and current.end_byte == fn.end:
                break
            if current.type in BLOCK_TYPES:
                names = self.block_decls.get((current.start_byte, current.end_byte))
                if names and name in names:
                    return f"{name}#{current.start_byte}"
            current = current.parent
        return name

    def _collect_functions(self) -> None:
        self._collect_block_declarations()
        root = self.tree.root_node
        module = FunctionInfo(name="<module>", node=root, params=[], line=1, is_module=True)
        self.functions.append(module)

        for node in parser.walk(root):
            if node.type not in parser.FUNCTION_TYPES:
                continue
            info = FunctionInfo(
                name=self._function_name(node),
                node=node,
                params=self._parameters(node),
                line=parser.line_of(node),
                is_promise_executor=self._is_promise_executor(node),
            )
            self.functions.append(info)

        # Relacion de anidamiento: la funcion contenedora mas pequena.
        ordered = sorted(self.functions, key=lambda f: f.end - f.start)
        for info in self.functions:
            if info.is_module:
                continue
            for candidate in ordered:
                if candidate is info:
                    continue
                if candidate.start <= info.start and candidate.end >= info.end:
                    info.parent = candidate
                    break

        for position, info in enumerate(self.functions):
            self._index[id(info)] = position
        for info in self.functions:
            self.by_span[(info.start, info.end)] = info
            if info.name and info.name not in self.by_name:
                self.by_name[info.name] = info
            if info.name and info.parent is not None:
                self.scoped.setdefault((id(info.parent), info.name), info)

    def _function_name(self, node: Any) -> str:
        named = parser.field(node, "name")
        if named is not None:
            return parser.text(named, self.source)
        holder = node.parent
        for _ in range(3):
            if holder is None:
                break
            if holder.type == "variable_declarator":
                target = parser.field(holder, "name")
                if target is not None:
                    return parser.text(target, self.source)
            if holder.type == "pair":
                key = parser.field(holder, "key")
                if key is not None:
                    return parser.text(key, self.source).strip("'\"")
            if holder.type == "assignment_expression":
                left = parser.field(holder, "left")
                if left is not None:
                    return parser.text(left, self.source).split(".")[-1]
            holder = holder.parent
        return f"<anonima@{parser.line_of(node)}>"

    def _parameters(self, node: Any) -> list[str]:
        container = parser.field(node, "parameters") or parser.field(node, "parameter")
        if container is None:
            return []
        if container.type == "identifier":
            return [parser.text(container, self.source)]
        names: list[str] = []
        for child in parser.walk(container):
            if child.type == "identifier" and child.parent is not None:
                # Evita capturar valores por defecto (`function f(a = g())`).
                if child.parent.type == "assignment_pattern" and parser.field(
                        child.parent, "right") is child:
                    continue
                name = parser.text(child, self.source)
                if name and name not in names:
                    names.append(name)
        return names

    def _is_promise_executor(self, node: Any) -> bool:
        holder = node.parent
        for _ in range(3):
            if holder is None:
                return False
            if holder.type == "new_expression":
                constructor = parser.field(holder, "constructor")
                return constructor is not None and parser.text(constructor, self.source) == "Promise"
            if holder.type != "arguments":
                return False
            holder = holder.parent
        return False

    # -- punto fijo -----------------------------------------------------
    def _fixpoint(self) -> None:
        for _ in range(MAX_ITERATIONS):
            self._changed = False
            self.param_calls = {}
            for info in self.functions:
                self._analyze_function(info)
            if self._propagate_calls():
                self._changed = True
            if not self._changed:
                break

    def _analyze_function(self, fn: FunctionInfo) -> None:
        fn.declared.update(fn.params)
        for name, value in fn.param_taint.items():
            merged = fn.variables.get(name, EMPTY).merge(value)
            if merged != fn.variables.get(name, EMPTY):
                fn.variables[name] = merged
                self._changed = True

        # Un parametro que ningun llamante conocido alimenta puede seguir
        # transportando material sensible: es el caso de los callbacks
        # (`onSign(keyBytes, password)`), cuyo invocador esta en otro script o
        # es una API del navegador. Se siembra por heuristica de nombre, que
        # produce confianza baja y exige revision manual.
        if self.symbolic:
            # Cada parametro es un marcador: "lo que el llamante pase aqui".
            position_of = self._index[id(fn)]
            for position, param in enumerate(fn.params):
                marker = TaintValue(labels=frozenset({f"{MARKER}{position_of}:{position}"}))
                merged = fn.variables.get(param, EMPTY).merge(marker)
                if merged != fn.variables.get(param, EMPTY):
                    fn.variables[param] = merged
                    self._changed = True
        for param in ([] if self.symbolic else fn.params):
            if not fn.param_taint.get(param, EMPTY).empty:
                continue
            if not fn.variables.get(param, EMPTY).empty:
                continue
            seed = self._name_seed(param, fn.node, "parametro")
            if not seed.empty:
                fn.variables[param] = seed
                self._changed = True

        body = parser.field(fn.node, "body") or fn.node
        # Dos pasadas: la segunda recoge usos anteriores a la declaracion
        # (hoisting, bucles) sin necesidad de un analisis de flujo completo.
        # Cada pasada reconstruye calls/sinks para no duplicarlos.
        for _ in range(2):
            fn.calls = []
            fn.sinks = []
            # El cuerpo de una arrow function puede ser la propia expresion
            # (`x => fetch(url, x)`), asi que se visita ademas de sus hijos.
            self._visit(body, fn)
            for node in parser.walk_scoped(body):
                self._visit(node, fn)

    def _visit(self, node: Any, fn: FunctionInfo) -> None:
        kind = node.type
        if kind == "variable_declarator":
            target = parser.field(node, "name")
            value = parser.field(node, "value")
            if target is not None and target.type == "identifier":
                name = self._bind(parser.text(target, self.source), target, fn)
                fn.declared.add(name)
                taint = self._taint_of(value, fn) if value is not None else EMPTY
                if taint.empty:
                    taint = self._name_seed(name, target)
                self._assign(fn, name, taint)
        elif kind in ("assignment_expression", "augmented_assignment_expression"):
            self._visit_assignment(node, fn)
        elif kind == "return_statement":
            values = [c for c in node.named_children]
            if values:
                self._merge_returns(fn, self._taint_of(values[0], fn))
        elif kind == "call_expression":
            self._visit_call(node, fn)

    def _visit_assignment(self, node: Any, fn: FunctionInfo) -> None:
        left = parser.field(node, "left")
        right = parser.field(node, "right")
        if left is None:
            return
        taint = self._taint_of(right, fn) if right is not None else EMPTY
        if node.type == "augmented_assignment_expression":
            taint = taint.merge(self._taint_of(left, fn))

        if left.type == "identifier":
            # Una asignacion sin declaracion puede alcanzar un ambito exterior.
            owner, key = self._scope_for(fn, parser.text(left, self.source), left)
            self._assign(owner, key, taint)
            return

        if left.type in ("member_expression", "subscript_expression"):
            member = parser.field(left, "property")
            member_name = parser.text(member, self.source) if member is not None else ""
            obj = parser.field(left, "object")
            object_text = parser.text(obj, self.source) if obj is not None else ""
            pattern = catalog.match_pattern(catalog.SINK_ASSIGNMENTS, member_name, object_text)
            if pattern is not None and not taint.empty:
                fn.sinks.append(SinkSite(
                    pattern=pattern, node=node, data_nodes=[right] if right is not None else [],
                    url_node=right, function=fn, line=parser.line_of(node),
                    snippet=parser.snippet(node, self.source)))
            # `obj.prop = sensible` contamina el objeto contenedor.
            if obj is not None and obj.type == "identifier" and not taint.empty:
                owner, key = self._scope_for(fn, parser.text(obj, self.source), obj)
                self._assign(owner, key, taint)

    def _visit_call(self, node: Any, fn: FunctionInfo) -> None:
        callee = parser.field(node, "function")
        if callee is None:
            return
        args = self._arguments(node)
        member_name, object_node = self._callee_parts(callee)
        object_text = parser.text(object_node, self.source) if object_node is not None else ""
        callee_text = parser.text(callee, self.source)

        # 1. Sources de tipo FileReader: contaminan el objeto receptor.
        source_pattern = catalog.match_pattern(catalog.SOURCE_CALLS, member_name, object_text)
        if source_pattern is not None and object_node is not None and object_node.type == "identifier":
            incoming = EMPTY
            for arg in args:
                incoming = incoming.merge(self._taint_of(arg, fn))
            labels = set(source_pattern.labels) | catalog.infer_labels(callee_text)
            if incoming.empty and labels:
                incoming = TaintValue(
                    labels=frozenset(labels),
                    origin=SourceRef(source_pattern.name, "api", parser.line_of(node),
                                     parser.snippet(node, self.source)),
                )
            if not incoming.empty:
                owner, key = self._scope_for(fn, parser.text(object_node, self.source), object_node)
                self._assign(owner, key, incoming)

        # 2. Continuaciones de promesa: `resolve(x)` equivale a un retorno.
        if callee.type == "identifier" and self._is_continuation(fn, callee_text):
            for arg in args:
                value = self._taint_of(arg, fn)
                if not value.empty:
                    self._merge_returns(self._promise_owner(fn), value)

        # 3. Callbacks encadenados: `.then(cb)` siembra el primer parametro.
        if member_name in ("then", "catch", "finally") and object_node is not None:
            upstream = self._taint_of(object_node, fn)
            if not upstream.empty:
                for arg in args:
                    self._seed_callback(arg, upstream)

        # 4. Sinks.
        pattern = catalog.match_pattern(catalog.SINK_CALLS, member_name, object_text)
        if pattern is None and callee.type == "identifier":
            pattern = catalog.match_pattern(catalog.SINK_CALLS, callee_text, "")
        if pattern is not None:
            data_nodes = [args[i] for i in pattern.data_args if i < len(args)]
            url_node = args[pattern.url_arg] if (
                pattern.url_arg is not None and pattern.url_arg < len(args)) else None
            fn.sinks.append(SinkSite(
                pattern=pattern, node=node, data_nodes=data_nodes, url_node=url_node,
                function=fn, line=parser.line_of(node),
                snippet=parser.snippet(node, self.source)))

        # 4b. Acumuladores: `form.append('key', blob)` contamina a `form`.
        # Solo cuando la llamada no era ya un sumidero, para no reinterpretar
        # `localStorage.setItem(...)` — que consume el dato — como acumulacion.
        if (pattern is None and member_name in catalog.ACCUMULATOR_METHODS
                and object_node is not None and object_node.type == "identifier"):
            incoming = EMPTY
            for arg in args:
                incoming = incoming.merge(self._taint_of(arg, fn))
            if not incoming.empty:
                # No es una transformacion que oscurezca el dato: los bytes
                # siguen ahi, de modo que el resultado no se marca derivado.
                owner, key = self._scope_for(fn, parser.text(object_node, self.source), object_node)
                self._assign(owner, key, incoming.through(member_name, derived=False))

        # 5. Grafo de llamadas hacia funciones locales.
        owner = self._param_owner(callee_text, fn) if callee.type == "identifier" else None
        if owner is not None:
            # `cb(x)` donde cb es un parametro — propio o capturado por
            # clausura: la funcion real la decide quien llamo a `owner`. Se
            # resuelve en _propagate_calls.
            self.param_calls.setdefault(id(owner), {})[parser.node_key(node)] = \
                ParamCall(callee_text, args, fn)
            return
        target_name = callee_text if callee.type == "identifier" else member_name
        target = self._resolve_callee(callee, callee_text, member_name, fn)
        if target is not None:
            fn.calls.append(CallSite(target_name, node, args, fn, parser.line_of(node), target))
            self.call_edges.setdefault(target_name, set()).add(fn.label())

    def _seed_callback(self, arg: Any, upstream: TaintValue) -> None:
        if arg is None or arg.type not in parser.FUNCTION_TYPES:
            return
        for info in self.functions:
            if info.node.start_byte == arg.start_byte and info.node.end_byte == arg.end_byte:
                if info.params:
                    first = info.params[0]
                    current = info.param_taint.get(first, EMPTY)
                    merged = current.merge(upstream)
                    if merged != current:
                        info.param_taint[first] = merged
                        self._changed = True
                return

    def _propagate_calls(self) -> bool:
        changed = False
        for fn in self.functions:
            for call in fn.calls:
                callee = call.target
                if callee is None or self.symbolic:
                    continue
                if self._propagate_callbacks(call, callee, fn):
                    changed = True
                for index, param in enumerate(callee.params):
                    if index >= len(call.args):
                        break
                    value = self._taint_of(call.args[index], fn)
                    if value.empty:
                        continue
                    merged = callee.param_taint.get(param, EMPTY).merge(value.across_call())
                    if merged != callee.param_taint.get(param, EMPTY):
                        callee.param_taint[param] = merged
                        changed = True
        # El ejecutor de una promesa devuelve a traves de la funcion que la crea.
        for fn in self.functions:
            if fn.is_promise_executor and fn.parent is not None and not fn.returns.empty:
                merged = fn.parent.returns.merge(fn.returns)
                if merged != fn.parent.returns:
                    fn.parent.returns = merged
                    changed = True
        return changed

    def _resolve_callee(self, callee: Any, callee_text: str, member_name: str,
                        fn: FunctionInfo) -> FunctionInfo | None:
        """Funcion local a la que se refiere una llamada.

        Los identificadores se resuelven por ambito lexico, subiendo desde la
        funcion que llama. Un mapa global de nombres no basta: el codigo
        minificado reutiliza ``e``, ``n`` o ``t`` en cada ambito, y resolver
        ``n(x)`` a cualquier funcion global llamada ``n`` fabrica un grafo de
        llamadas falso. Un parametro con el mismo nombre oculta a las
        funciones exteriores.
        """
        # Funcion invocada en el acto: `(function (cb) {...})(handler)` o
        # `!function (cb) {...}(handler)`. Es lo que produce un bundler al
        # inlinar una funcion de un solo uso; sin esto, el callback que recibe
        # quedaba fuera del analisis.
        literal = callee
        while literal is not None and literal.type == "parenthesized_expression":
            literal = literal.named_children[0] if literal.named_children else None
        if literal is not None and literal.type in parser.FUNCTION_TYPES:
            return self.by_span.get((literal.start_byte, literal.end_byte))
        if callee.type != "identifier":
            return self.by_name.get(member_name)
        scope: FunctionInfo | None = fn
        while scope is not None:
            if callee_text in scope.params:
                return None
            hit = self.scoped.get((id(scope), callee_text))
            if hit is not None:
                return hit
            scope = scope.parent
        return None

    def _call_return(self, target: FunctionInfo, args: list[Any], fn: FunctionInfo,
                     depth: int) -> TaintValue:
        """Lo que devuelve *esta* llamada a ``target``.

        Se parte del resumen simbolico: sus etiquetas propias se conservan, y
        cada marcador de parametro se sustituye por la procedencia del
        argumento de esta llamada. Un marcador de otra funcion — un parametro
        exterior capturado por clausura — se sustituye por la procedencia
        acumulada de ese parametro, que es la aproximacion conservadora.
        """
        summary = target.returns if self.symbolic else self.summaries.get(self._index.get(id(target), -1))
        if summary is None:
            summary = target.returns
        if summary.empty:
            return EMPTY

        own = frozenset(label for label in summary.labels if not _is_marker(label))
        result = (TaintValue(own, summary.origin, summary.hops, summary.transforms, summary.derived)
                  if own else EMPTY)
        target_index = self._index.get(id(target), -1)
        for label in summary.labels:
            if not _is_marker(label):
                continue
            public_only = label.endswith(PUBLIC_SUFFIX)
            owner_index, position = (int(x) for x in label[len(MARKER):].split("|")[0].split(":"))
            if owner_index == target_index:
                value = self._taint_of(args[position], fn, depth + 1) if position < len(args) else EMPTY
            else:
                owner = self.functions[owner_index]
                name = owner.params[position] if position < len(owner.params) else ""
                value = owner.variables.get(name, EMPTY)
            if public_only and not value.empty:
                kept = frozenset(label_ for label_ in value.labels if label_ not in PRIVATE_LABELS)
                value = TaintValue(kept, value.origin, value.hops, value.transforms, value.derived) \
                    if kept else EMPTY
            if value.empty:
                continue
            result = result.merge(TaintValue(
                value.labels, value.origin, value.hops,
                _merge_transforms(value.transforms, summary.transforms),
                value.derived or summary.derived,
            ))
        if result.empty:
            return EMPTY
        return result.across_call().through(target.label(), derived=False)

    def _param_owner(self, name: str, fn: FunctionInfo) -> FunctionInfo | None:
        """La funcion, propia o exterior, de la que ``name`` es parametro.

        Se detiene si antes encuentra una funcion local con ese nombre: en
        ese caso ``name`` no es el parametro sino esa funcion.
        """
        scope: FunctionInfo | None = fn
        while scope is not None:
            if name in scope.params:
                return scope
            if (id(scope), name) in self.scoped:
                return None
            scope = scope.parent
        return None

    def _function_value(self, node: Any, fn: FunctionInfo) -> FunctionInfo | None:
        """La funcion local que denota una expresion, si denota alguna."""
        if node is None:
            return None
        if node.type in parser.FUNCTION_TYPES:
            return self.by_span.get((node.start_byte, node.end_byte))
        if node.type == "identifier":
            return self._resolve_callee(node, parser.text(node, self.source), "", fn)
        return None

    def _propagate_callbacks(self, call: CallSite, callee: FunctionInfo,
                             caller: FunctionInfo) -> bool:
        """Propagacion de orden superior: ``run(function (k) {...})``.

        Si ``run`` invoca su parametro con datos sensibles (``cb(keyBytes)``),
        esos datos llegan a los parametros de la funcion que el llamante paso.
        Es el patron de todo manejador de eventos y de casi cualquier
        biblioteca; sin el, la procedencia se detenia en cada callback.
        """
        changed = False
        for index, arg in enumerate(call.args):
            if index >= len(callee.params):
                break
            handler = self._function_value(arg, caller)
            if handler is None:
                continue
            param = callee.params[index]
            for param_call in self.param_calls.get(id(callee), {}).values():
                if param_call.param != param:
                    continue
                for position, value_node in enumerate(param_call.args):
                    if position >= len(handler.params):
                        break
                    value = self._taint_of(value_node, param_call.evaluator)
                    if value.empty:
                        continue
                    target_param = handler.params[position]
                    current = handler.param_taint.get(target_param, EMPTY)
                    merged = current.merge(value.across_call())
                    if merged != current:
                        handler.param_taint[target_param] = merged
                        changed = True
        return changed

    def _assign(self, fn: FunctionInfo, name: str, value: TaintValue) -> bool:
        if not name or value.empty:
            return False
        current = fn.variables.get(name, EMPTY)
        merged = current.merge(value)
        if merged == current:
            return False
        fn.variables[name] = merged
        self._changed = True
        return True

    def _merge_returns(self, fn: FunctionInfo, value: TaintValue) -> None:
        if value.empty:
            return
        merged = fn.returns.merge(value)
        if merged != fn.returns:
            fn.returns = merged
            self._changed = True

    def _lookup(self, fn: FunctionInfo, name: str, node: Any = None) -> TaintValue:
        """Resuelve un identificador recorriendo la cadena de ambitos."""
        current: FunctionInfo | None = fn
        while current is not None:
            value = current.variables.get(self._bind(name, node, current))
            if value is not None and not value.empty:
                return value
            current = current.parent
        return EMPTY

    def _scope_for(self, fn: FunctionInfo, name: str, node: Any = None) -> tuple[FunctionInfo, str]:
        """Ambito y clave a los que pertenece ``name``; los propios si no se
        declaro antes."""
        current: FunctionInfo | None = fn
        while current is not None:
            key = self._bind(name, node, current)
            if key in current.declared:
                return current, key
            current = current.parent
        return fn, self._bind(name, node, fn)

    def _is_continuation(self, fn: FunctionInfo, name: str) -> bool:
        """True si ``name`` es el ``resolve`` de un ejecutor de promesa en ambito."""
        current: FunctionInfo | None = fn
        while current is not None:
            if current.is_promise_executor and name in current.params[:1]:
                return True
            current = current.parent
        return False

    def _promise_owner(self, fn: FunctionInfo) -> FunctionInfo:
        current: FunctionInfo | None = fn
        while current is not None:
            if current.is_promise_executor:
                return current
            current = current.parent
        return fn

    # -- evaluacion de expresiones --------------------------------------
    def _taint_of(self, node: Any, fn: FunctionInfo, depth: int = 0) -> TaintValue:
        if node is None or depth > 12:
            return EMPTY
        kind = node.type

        # Una funcion como valor no transporta procedencia: su contenido se
        # analiza por separado, con su propio estado.
        if kind in parser.FUNCTION_TYPES:
            return EMPTY

        if kind == "identifier":
            return self._lookup(fn, parser.text(node, self.source), node)

        if kind in ("parenthesized_expression", "await_expression", "unary_expression",
                    "spread_element", "expression_statement", "non_null_expression"):
            result = EMPTY
            for child in node.named_children:
                result = result.merge(self._taint_of(child, fn, depth + 1))
            return result

        if kind in ("member_expression", "subscript_expression"):
            return self._taint_of_member(node, fn, depth)

        if kind == "call_expression":
            return self._taint_of_call(node, fn, depth)

        if kind == "new_expression":
            constructor = parser.field(node, "constructor")
            name = parser.text(constructor, self.source) if constructor is not None else ""
            result = EMPTY
            for arg in self._arguments(node):
                result = result.merge(self._taint_of(arg, fn, depth + 1))
            if result.empty:
                return EMPTY
            if name in catalog.TRANSFORM_CONSTRUCTORS:
                # Todos son envoltorios (Blob, FormData, Uint8Array...): el
                # contenido viaja intacto dentro, asi que la salida sigue
                # siendo una transmision directa del material.
                return result.through(f"new {name}", derived=False)
            return result

        if kind in ("object", "array", "arguments", "template_string", "template_substitution",
                    "binary_expression", "ternary_expression", "pair", "sequence_expression",
                    "assignment_expression", "augmented_assignment_expression"):
            result = EMPTY
            for child in node.named_children:
                result = result.merge(self._taint_of(child, fn, depth + 1))
            return result

        if kind == "shorthand_property_identifier":
            return self._lookup(fn, parser.text(node, self.source), node)

        if kind in ("string", "number", "true", "false", "null", "undefined", "regex"):
            return EMPTY

        # Nodos no contemplados: se exploran los hijos con nombre.
        result = EMPTY
        for child in node.named_children:
            result = result.merge(self._taint_of(child, fn, depth + 1))
        return result

    def _taint_of_member(self, node: Any, fn: FunctionInfo, depth: int) -> TaintValue:
        obj = parser.field(node, "object")
        prop = parser.field(node, "property") or parser.field(node, "index")
        prop_name = parser.text(prop, self.source) if prop is not None else ""
        base = self._taint_of(obj, fn, depth + 1) if obj is not None else EMPTY

        full_text = parser.text(node, self.source)
        pattern = catalog.match_pattern(
            catalog.SOURCE_PROPERTIES, prop_name,
            parser.text(obj, self.source) if obj is not None else "")
        if (pattern is None and prop_name in catalog.DOM_CONTENT_PROPERTIES
                and base.origin is not None and base.origin.kind == "dom"):
            # `el.value` / `el.files` sobre un elemento identificado por su
            # selector: la lectura es una fuente real, y la etiqueta la aporta
            # el id del campo.
            pattern = next((c for c in catalog.SOURCE_PROPERTIES if c.member == prop_name), None)
        if pattern is not None:
            labels = set(pattern.labels) | catalog.infer_labels(full_text)
            if base.origin is not None and base.origin.kind == "dom":
                labels |= set(base.labels)
            if labels:
                return base.merge(TaintValue(
                    labels=frozenset(labels),
                    origin=SourceRef(pattern.name, "api", parser.line_of(node),
                                     parser.snippet(node, self.source)),
                ))
        # Un elemento identificado por su selector solo entrega material al
        # leer su contenido (arriba). `el.offsetWidth` o `el.dataset` no son
        # el campo de la contrasena, aunque el elemento lo sea.
        if _dom_hint_only(base):
            return EMPTY
        # El acceso a miembro hereda la procedencia del objeto: `loaded.pkcs8`,
        # `reader.result` o `files[0]` siguen siendo el mismo material.
        return base

    def _taint_of_call(self, node: Any, fn: FunctionInfo, depth: int) -> TaintValue:
        callee = parser.field(node, "function")
        if callee is None:
            return EMPTY
        member_name, object_node = self._callee_parts(callee)
        callee_text = parser.text(callee, self.source)
        args = self._arguments(node)

        # Un elemento del DOM identificado por un selector literal lleva como
        # pista lo que el selector sugiere ("key-file", "password"). No es
        # material sensible por si mismo: la pista solo cuenta cuando se lee
        # su contenido (ver DOM_CONTENT_PROPERTIES).
        if member_name in catalog.DOM_LOOKUPS and args and args[0].type == "string":
            selector = parser.text(args[0], self.source).strip("'\"`")
            hinted = catalog.infer_labels(selector)
            if hinted:
                return TaintValue(
                    labels=frozenset(hinted),
                    origin=SourceRef(f"elemento: {selector}", "dom", parser.line_of(node),
                                     parser.snippet(node, self.source)),
                )
            return EMPTY

        incoming = EMPTY
        for arg in args:
            incoming = incoming.merge(self._taint_of(arg, fn, depth + 1))

        # Llamada a una funcion local: el valor devuelto vuelve al llamante.
        target = self._resolve_callee(callee, callee_text, member_name, fn)
        if target is not None and target is not fn:
            # Una funcion local con resumen: el resumen dice exactamente que
            # parametros llegan al retorno. Unir ademas todos los argumentos
            # — el tratamiento generico de una llamada desconocida — haria que
            # `signDocument(privateKey, doc)` devolviera la clave privada.
            return self._call_return(target, args, fn, depth)

        pattern = catalog.match_pattern(catalog.SOURCE_CALLS, member_name, callee_text)
        if pattern is not None:
            labels = set(pattern.labels) | catalog.infer_labels(callee_text)
            source = SourceRef(pattern.name, "api", parser.line_of(node),
                               parser.snippet(node, self.source))
            if member_name == "sign":
                # S3 + S5 --sign--> S6 es la transformacion legitima del modelo.
                # La firma es el producto que la aplicacion debe enviar, asi que
                # no hereda la procedencia privada: hacerlo convertiria cada
                # envio de firma de un sitio correcto en un falso positivo.
                public = {label for label in incoming.labels - PRIVATE_LABELS
                          if not _is_marker(label)}
                markers = {label.split("|")[0] + PUBLIC_SUFFIX
                           for label in incoming.labels if _is_marker(label)}
                return TaintValue(
                    labels=frozenset({Tag.SIGNATURE.value} | public | markers),
                    origin=source,
                    hops=incoming.hops,
                    transforms=_merge_transforms(incoming.transforms, (pattern.name,)),
                    derived=True,
                )
            if member_name == "decrypt" and Tag.KEY_FILE.value in incoming.labels:
                # .key cifrado + contrasena -> clave privada en claro
                labels.add(Tag.PRIVATE_KEY.value)
            if incoming.empty and labels:
                return TaintValue(labels=frozenset(labels), origin=source)
            if not incoming.empty:
                value = incoming.through(pattern.name, derived=catalog.obscures(pattern.name))
                if value.origin is None:
                    value = TaintValue(value.labels, source, value.hops, value.transforms, value.derived)
                return value.with_labels(labels)

        if incoming.empty:
            return EMPTY
        name = member_name or callee_text
        if catalog.is_transform(member_name) or catalog.is_transform(callee_text):
            return incoming.through(name, derived=catalog.obscures(name))
        if object_node is not None:
            base = self._taint_of(object_node, fn, depth + 1)
            # Los metodos de un elemento (`el.getAttribute(...)`) tampoco
            # entregan su contenido.
            if _dom_hint_only(base):
                base = EMPTY
            if not base.empty:
                return incoming.merge(base).through(name, derived=catalog.obscures(name))
        return incoming.through(member_name or callee_text, derived=False)

    def _callee_parts(self, callee: Any) -> tuple[str, Any | None]:
        if callee.type in ("member_expression", "subscript_expression"):
            prop = parser.field(callee, "property") or parser.field(callee, "index")
            return (parser.text(prop, self.source) if prop is not None else "",
                    parser.field(callee, "object"))
        return parser.text(callee, self.source), None

    def _arguments(self, node: Any) -> list[Any]:
        container = parser.field(node, "arguments")
        if container is None:
            return []
        return [child for child in container.named_children if child.type != "comment"]

    def _name_seed(self, name: str, node: Any, kind: str = "identificador") -> TaintValue:
        """Siembra por heuristica de nombre, con confianza baja."""
        labels = catalog.infer_labels(name)
        if not labels:
            return EMPTY
        return TaintValue(
            labels=frozenset(labels),
            origin=SourceRef(f"{kind}: {name}", "name", parser.line_of(node),
                             parser.snippet(node, self.source)),
        )

    # -- extraccion de rutas --------------------------------------------
    def _collect_paths(self) -> None:
        seen: set[tuple[str, int, str]] = set()
        for fn in self.functions:
            for sink in fn.sinks:
                value = EMPTY
                for data_node in sink.data_nodes:
                    value = value.merge(self._taint_of(data_node, fn))
                if sink.url_node is not None:
                    value = value.merge(self._taint_of(sink.url_node, fn))
                if value.empty or value.origin is None:
                    continue
                key = (sink.pattern.name, sink.line, ",".join(sorted(value.labels)))
                if key in seen:
                    continue
                seen.add(key)
                self.paths.append(StaticPath(
                    source=value.origin,
                    sink_name=sink.pattern.name,
                    sink_snippet=sink.snippet,
                    sink_line=sink.line,
                    channel=sink.pattern.channel,
                    labels=sorted(value.labels),
                    transforms=list(value.transforms),
                    confidence=value.confidence(),
                    call_chain=self._call_chain(fn),
                    file_label=self.file_label,
                    url=self.url,
                    hops=value.hops,
                    derived=value.derived,
                ))

    def _call_chain(self, fn: FunctionInfo) -> list[str]:
        """Reconstruye la cadena de llamadas que alcanza a ``fn``."""
        chain = [f"{fn.label()}()"]
        current = fn.label()
        visited = {current}
        while len(chain) < MAX_CALL_CHAIN:
            callers = self.call_edges.get(current)
            if not callers:
                break
            nxt = sorted(callers - visited)
            if not nxt:
                break
            current = nxt[0]
            visited.add(current)
            chain.insert(0, f"{current}()")
        return chain
