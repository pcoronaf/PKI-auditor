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
        if self.origin.kind == "name":
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

    def __init__(self, source: bytes, file_label: str, url: str = ""):
        self.source = source
        self.file_label = file_label
        self.url = url
        self.tree = parser.parse(source)
        self.functions: list[FunctionInfo] = []
        self.by_name: dict[str, FunctionInfo] = {}
        self.call_edges: dict[str, set[str]] = {}
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
        self._fixpoint()
        self._collect_paths()
        return self.paths

    # -- recoleccion de funciones ---------------------------------------
    def _collect_functions(self) -> None:
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

        for info in self.functions:
            if info.name and info.name not in self.by_name:
                self.by_name[info.name] = info

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
        for param in fn.params:
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
                name = parser.text(target, self.source)
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
            name = parser.text(left, self.source)
            # Una asignacion sin declaracion puede alcanzar un ambito exterior.
            self._assign(self._scope_for(fn, name), name, taint)
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
                self._assign(fn, parser.text(obj, self.source), taint)

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
                self._assign(fn, parser.text(object_node, self.source), incoming)

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
                self._assign(fn, parser.text(object_node, self.source),
                             incoming.through(member_name, derived=False))

        # 5. Grafo de llamadas hacia funciones locales.
        target_name = callee_text if callee.type == "identifier" else member_name
        if target_name in self.by_name:
            fn.calls.append(CallSite(target_name, node, args, fn, parser.line_of(node)))
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
                callee = self.by_name.get(call.callee)
                if callee is None:
                    continue
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

    def _lookup(self, fn: FunctionInfo, name: str) -> TaintValue:
        """Resuelve un identificador recorriendo la cadena de ambitos."""
        current: FunctionInfo | None = fn
        while current is not None:
            value = current.variables.get(name)
            if value is not None and not value.empty:
                return value
            current = current.parent
        return EMPTY

    def _scope_for(self, fn: FunctionInfo, name: str) -> FunctionInfo:
        """Ambito al que pertenece ``name``; el propio si no se declaro antes."""
        current: FunctionInfo | None = fn
        while current is not None:
            if name in current.declared:
                return current
            current = current.parent
        return fn

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
            return self._lookup(fn, parser.text(node, self.source))

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
            return self._lookup(fn, parser.text(node, self.source))

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
        if pattern is not None:
            labels = set(pattern.labels) | catalog.infer_labels(full_text)
            if labels:
                return base.merge(TaintValue(
                    labels=frozenset(labels),
                    origin=SourceRef(pattern.name, "api", parser.line_of(node),
                                     parser.snippet(node, self.source)),
                ))
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

        incoming = EMPTY
        for arg in args:
            incoming = incoming.merge(self._taint_of(arg, fn, depth + 1))

        # Llamada a una funcion local: el valor devuelto vuelve al llamante.
        target = self.by_name.get(callee_text if callee.type == "identifier" else member_name)
        if target is not None and target is not fn and not target.returns.empty:
            returned = target.returns.across_call().through(target.label(), derived=False)
            incoming = incoming.merge(returned)

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
                return TaintValue(
                    labels=frozenset({Tag.SIGNATURE.value} | (incoming.labels - PRIVATE_LABELS)),
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
