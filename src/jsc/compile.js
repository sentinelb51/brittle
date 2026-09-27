// jsc/compile.js — compile a marked JS function into brittle JS-engine bytecode (src/jsvm/vm.js).
// This is the "feed a .js file / mark a function" front end. acorn parses to an AST; we
// lower a supported subset to a stack-machine module: { consts, names, functions, entry }.
//
// v1 supported: numbers/strings/booleans/null/undefined, let/const/var, arithmetic, bitwise,
// comparison, logical (&& || ?? with short-circuit), ternary, unary (- ! ~ + typeof void),
// update (++/--), assignment (= and compound), if/else, while, do/while, for, break/continue
// (unlabeled), return, function decls/exprs/arrows, closures, calls + method calls, member
// access, arrays, objects, template literals, sequence.
//
// v1 NOT supported (thrown with a clear message): this, new, class, try/catch, for-in/of,
// async/await, generators, spread/rest, destructuring, labeled break, computed compound
// assignment/update, getters/setters, delete, with, tagged templates, regex literals.
//
// Parity: arithmetic/compare/logic use native operators in the engine, so a supported function
// produces identical results to running the original source. test/jsvm.mjs checks this.

import { parse } from "acorn";
import { OP } from "../jsvm/vm.js";

// Operator -> opcode tables. Hoisted to module scope so they are built once, not
// reallocated on every node the compiler visits.
const BIN_OP = {
  "+": OP.ADD, "-": OP.SUB, "*": OP.MUL, "/": OP.DIV, "%": OP.MOD, "**": OP.POW,
  "<": OP.LT, "<=": OP.LE, ">": OP.GT, ">=": OP.GE, "==": OP.EQ, "!=": OP.NE,
  "===": OP.SEQ, "!==": OP.SNE, "&": OP.BAND, "|": OP.BOR, "^": OP.BXOR,
  "<<": OP.SHL, ">>": OP.SHR, ">>>": OP.USHR,
};
const UNARY_OP = { "-": OP.NEG, "!": OP.NOT, "~": OP.BNOT, "+": OP.UPLUS, typeof: OP.TYPEOF };
const COMPOUND_OP = {
  "+=": OP.ADD, "-=": OP.SUB, "*=": OP.MUL, "/=": OP.DIV, "%=": OP.MOD, "**=": OP.POW,
  "&=": OP.BAND, "|=": OP.BOR, "^=": OP.BXOR, "<<=": OP.SHL, ">>=": OP.SHR, ">>>=": OP.USHR,
};

class Compiler {
  constructor() {
    this.consts = [];
    this.names = [];
    this.functions = [];
  }
  constIndex(v) {
    // primitives dedupe by ===; keep NaN distinct-safe
    for (let i = 0; i < this.consts.length; i++) if (Object.is(this.consts[i], v)) return i;
    this.consts.push(v);
    return this.consts.length - 1;
  }
  nameIndex(s) {
    const i = this.names.indexOf(s);
    if (i >= 0) return i;
    this.names.push(s);
    return this.names.length - 1;
  }

  // Compile a function AST node into a FnProto; returns its index in functions[].
  compileFn(node, parentFn) {
    const proto = { name: node.id?.name || "", numParams: node.params.length, numSlots: 0, code: [] };
    const idx = this.functions.length;
    this.functions.push(proto);
    const fn = {
      proto,
      parent: parentFn,
      scopes: [new Map()],
      loops: [],
      emit: (...ins) => (proto.code.push(ins), proto.code.length - 1),
      here: () => proto.code.length,
      alloc: () => proto.numSlots++,
      code: (i) => proto.code[i], // backpatch accessor for jump targets
    };

    // params occupy the first slots
    for (const p of node.params) {
      if (p.type !== "Identifier") this.unsupported(p, "only simple parameters");
      this.declare(fn, p.name);
    }

    // Entry self-binding: the top marked function has no lexical parent to hold its own
    // name, so bind it to a slot and store a self-closure. Safe because the entry has no
    // enclosing user scope (no upvalues to misresolve). Nested `function` declarations
    // recurse via block hoisting instead (their name lives in the defining scope).
    if (parentFn === null && node.id) {
      const selfSlot = this.declare(fn, node.id.name);
      fn.emit(OP.MAKE_CLOSURE, idx);
      fn.emit(OP.STORE, selfSlot);
    }

    const body = node.body;
    if (body.type === "BlockStatement") {
      this.compileBlockInner(fn, body.body);
    } else {
      // arrow with expression body: `=> expr` means `return expr`
      this.compileExpr(fn, body);
      fn.emit(OP.RET);
    }
    // guarantee a return
    fn.emit(OP.PUSH_UNDEF);
    fn.emit(OP.RET);
    return idx;
  }

  // ---- scope ----
  declare(fn, name) {
    const slot = fn.alloc();
    fn.scopes[fn.scopes.length - 1].set(name, slot);
    return slot;
  }
  // get-or-create a slot in the current block scope (idempotent within a block)
  declareLocal(fn, name) {
    const sc = fn.scopes[fn.scopes.length - 1];
    if (sc.has(name)) return sc.get(name);
    return this.declare(fn, name);
  }
  resolve(fn, name) {
    for (let f = fn, hops = 0; f; f = f.parent, hops++) {
      for (let i = f.scopes.length - 1; i >= 0; i--) {
        if (f.scopes[i].has(name)) return { hops, slot: f.scopes[i].get(name) };
      }
    }
    return null; // global
  }

  // ---- statements ----
  compileBlock(fn, node) {
    fn.scopes.push(new Map());
    this.compileBlockInner(fn, node.body);
    fn.scopes.pop();
  }
  compileBlockInner(fn, stmts) {
    // Pre-declare every name bound in this block (let/const/var + function decls) BEFORE
    // compiling any inner function body, so closures can capture outer variables that
    // appear later textually (real hoisting semantics; TDZ is not modeled in v1).
    for (const s of stmts) {
      if (s.type === "VariableDeclaration") {
        for (const d of s.declarations) if (d.id.type === "Identifier") this.declareLocal(fn, d.id.name);
      } else if (s.type === "FunctionDeclaration") {
        this.declareLocal(fn, s.id.name);
      }
    }
    // Initialize function declarations at block top (hoisted value).
    for (const s of stmts) {
      if (s.type === "FunctionDeclaration") {
        const slot = this.declareLocal(fn, s.id.name);
        const fi = this.compileFn(s, fn);
        fn.emit(OP.MAKE_CLOSURE, fi);
        fn.emit(OP.STORE, slot);
      }
    }
    for (const s of stmts) this.compileStmt(fn, s);
  }
  compileStmt(fn, s) {
    switch (s.type) {
      case "FunctionDeclaration":
        return; // already hoisted
      case "EmptyStatement":
        return;
      case "BlockStatement":
        return this.compileBlock(fn, s);
      case "VariableDeclaration":
        for (const d of s.declarations) {
          if (d.id.type !== "Identifier") this.unsupported(d.id, "destructuring");
          const slot = this.declareLocal(fn, d.id.name); // pre-declared by the block pass
          if (d.init) {
            this.compileExpr(fn, d.init);
            fn.emit(OP.STORE, slot);
          }
        }
        return;
      case "ExpressionStatement":
        this.compileExpr(fn, s.expression);
        fn.emit(OP.POP);
        return;
      case "ReturnStatement":
        if (s.argument) this.compileExpr(fn, s.argument);
        else fn.emit(OP.PUSH_UNDEF);
        fn.emit(OP.RET);
        return;
      case "IfStatement": {
        this.compileExpr(fn, s.test);
        const jElse = fn.emit(OP.JMP_IF_FALSE, -1);
        this.compileStmt(fn, s.consequent);
        if (s.alternate) {
          const jEnd = fn.emit(OP.JMP, -1);
          fn.code(jElse)[1] = fn.here();
          this.compileStmt(fn, s.alternate);
          fn.code(jEnd)[1] = fn.here();
        } else {
          fn.code(jElse)[1] = fn.here();
        }
        return;
      }
      case "WhileStatement": {
        const top = fn.here();
        this.compileExpr(fn, s.test);
        const jOut = fn.emit(OP.JMP_IF_FALSE, -1);
        fn.loops.push({ breaks: [], continues: [] });
        this.compileStmt(fn, s.body);
        const ctx = fn.loops.pop();
        fn.emit(OP.JMP, top);
        const end = fn.here();
        for (const j of ctx.breaks) fn.code(j)[1] = end;
        for (const j of ctx.continues) fn.code(j)[1] = top;
        fn.code(jOut)[1] = end;
        return;
      }
      case "DoWhileStatement": {
        const top = fn.here();
        fn.loops.push({ breaks: [], continues: [] });
        this.compileStmt(fn, s.body);
        const ctx = fn.loops.pop();
        const testAt = fn.here();
        this.compileExpr(fn, s.test);
        fn.emit(OP.JMP_IF_TRUE, top);
        const end = fn.here();
        for (const j of ctx.breaks) fn.code(j)[1] = end;
        for (const j of ctx.continues) fn.code(j)[1] = testAt;
        return;
      }
      case "ForStatement": {
        fn.scopes.push(new Map());
        if (s.init) {
          if (s.init.type === "VariableDeclaration") this.compileStmt(fn, s.init);
          else { this.compileExpr(fn, s.init); fn.emit(OP.POP); }
        }
        const top = fn.here();
        let jOut = -1;
        if (s.test) { this.compileExpr(fn, s.test); jOut = fn.emit(OP.JMP_IF_FALSE, -1); }
        fn.loops.push({ breaks: [], continues: [] });
        this.compileStmt(fn, s.body);
        const ctx = fn.loops.pop();
        const updateAt = fn.here();
        if (s.update) { this.compileExpr(fn, s.update); fn.emit(OP.POP); }
        fn.emit(OP.JMP, top);
        const end = fn.here();
        for (const j of ctx.breaks) fn.code(j)[1] = end;
        for (const j of ctx.continues) fn.code(j)[1] = updateAt;
        if (jOut >= 0) fn.code(jOut)[1] = end;
        fn.scopes.pop();
        return;
      }
      case "BreakStatement": {
        if (s.label) this.unsupported(s, "labeled break");
        if (!fn.loops.length) this.unsupported(s, "break outside loop");
        fn.loops[fn.loops.length - 1].breaks.push(fn.emit(OP.JMP, -1));
        return;
      }
      case "ContinueStatement": {
        if (s.label) this.unsupported(s, "labeled continue");
        if (!fn.loops.length) this.unsupported(s, "continue outside loop");
        fn.loops[fn.loops.length - 1].continues.push(fn.emit(OP.JMP, -1));
        return;
      }
      default:
        this.unsupported(s, s.type);
    }
  }

  // ---- expressions (each leaves exactly one value on the stack) ----
  compileExpr(fn, e) {
    switch (e.type) {
      case "Literal":
        if (e.value === null) return void fn.emit(OP.PUSH_NULL);
        if (e.value === true) return void fn.emit(OP.PUSH_TRUE);
        if (e.value === false) return void fn.emit(OP.PUSH_FALSE);
        if (e.regex) this.unsupported(e, "regex literal");
        return void fn.emit(OP.PUSH_CONST, this.constIndex(e.value));
      case "Identifier":
        return void this.emitLoadIdent(fn, e.name);
      case "TemplateLiteral": {
        // "".concat semantics via +; interleave quasis and expressions
        fn.emit(OP.PUSH_CONST, this.constIndex(e.quasis[0].value.cooked));
        for (let i = 0; i < e.expressions.length; i++) {
          this.compileExpr(fn, e.expressions[i]);
          fn.emit(OP.ADD);
          fn.emit(OP.PUSH_CONST, this.constIndex(e.quasis[i + 1].value.cooked));
          fn.emit(OP.ADD);
        }
        return;
      }
      case "ArrayExpression":
        for (const el of e.elements) {
          if (!el || el.type === "SpreadElement") this.unsupported(e, "array holes/spread");
          this.compileExpr(fn, el);
        }
        return void fn.emit(OP.NEW_ARRAY, e.elements.length);
      case "ObjectExpression": {
        let n = 0;
        for (const p of e.properties) {
          if (p.type !== "Property" || p.kind !== "init" || p.computed) this.unsupported(p, "object spread/getter/computed");
          const key = p.key.type === "Identifier" ? p.key.name : p.key.value;
          fn.emit(OP.PUSH_CONST, this.constIndex(String(key)));
          this.compileExpr(fn, p.value); // shorthand: value is the Identifier
          n++;
        }
        return void fn.emit(OP.NEW_OBJECT, n);
      }
      case "SequenceExpression":
        for (let i = 0; i < e.expressions.length; i++) {
          this.compileExpr(fn, e.expressions[i]);
          if (i < e.expressions.length - 1) fn.emit(OP.POP);
        }
        return;
      case "BinaryExpression": {
        this.compileExpr(fn, e.left);
        this.compileExpr(fn, e.right);
        if (!(e.operator in BIN_OP)) this.unsupported(e, "operator " + e.operator);
        return void fn.emit(BIN_OP[e.operator]);
      }
      case "LogicalExpression": {
        this.compileExpr(fn, e.left);
        fn.emit(OP.DUP);
        if (e.operator === "&&") {
          const j = fn.emit(OP.JMP_IF_FALSE, -1);
          fn.emit(OP.POP); this.compileExpr(fn, e.right);
          fn.code(j)[1] = fn.here();
        } else if (e.operator === "||") {
          const j = fn.emit(OP.JMP_IF_TRUE, -1);
          fn.emit(OP.POP); this.compileExpr(fn, e.right);
          fn.code(j)[1] = fn.here();
        } else if (e.operator === "??") {
          fn.emit(OP.PUSH_NULL); fn.emit(OP.EQ); // a == null  (true for null/undefined)
          const useB = fn.emit(OP.JMP_IF_TRUE, -1);
          const done = fn.emit(OP.JMP, -1);
          fn.code(useB)[1] = fn.here();
          fn.emit(OP.POP); this.compileExpr(fn, e.right);
          fn.code(done)[1] = fn.here();
        } else this.unsupported(e, "logical " + e.operator);
        return;
      }
      case "ConditionalExpression": {
        this.compileExpr(fn, e.test);
        const jElse = fn.emit(OP.JMP_IF_FALSE, -1);
        this.compileExpr(fn, e.consequent);
        const jEnd = fn.emit(OP.JMP, -1);
        fn.code(jElse)[1] = fn.here();
        this.compileExpr(fn, e.alternate);
        fn.code(jEnd)[1] = fn.here();
        return;
      }
      case "UnaryExpression": {
        if (e.operator === "void") { this.compileExpr(fn, e.argument); fn.emit(OP.POP); return void fn.emit(OP.PUSH_UNDEF); }
        if (e.operator === "typeof" && e.argument.type === "Identifier" && !this.resolve(fn, e.argument.name)) {
          // typeof undeclaredGlobal must not throw
          fn.emit(OP.PUSH_UNDEF); return void fn.emit(OP.TYPEOF);
        }
        this.compileExpr(fn, e.argument);
        if (!(e.operator in UNARY_OP)) this.unsupported(e, "unary " + e.operator);
        return void fn.emit(UNARY_OP[e.operator]);
      }
      case "UpdateExpression":
        return this.compileUpdate(fn, e);
      case "AssignmentExpression":
        return this.compileAssign(fn, e);
      case "MemberExpression":
        this.compileMemberGet(fn, e);
        return;
      case "CallExpression":
        return this.compileCall(fn, e);
      case "FunctionExpression":
      case "ArrowFunctionExpression": {
        if (e.type === "ArrowFunctionExpression" && e.async) this.unsupported(e, "async");
        const fi = this.compileFn(e, fn);
        return void fn.emit(OP.MAKE_CLOSURE, fi);
      }
      case "ParenthesizedExpression":
        return this.compileExpr(fn, e.expression);
      case "ThisExpression":
        this.unsupported(e, "this");
      case "NewExpression":
        this.unsupported(e, "new");
      default:
        this.unsupported(e, e.type);
    }
  }

  compileMemberGet(fn, e) {
    if (e.optional) this.unsupported(e, "optional chaining");
    this.compileExpr(fn, e.object);
    if (e.computed) { this.compileExpr(fn, e.property); fn.emit(OP.GET_PROP); }
    else fn.emit(OP.GET_PROP_C, this.constIndex(e.property.name));
  }

  compileCall(fn, e) {
    if (e.optional) this.unsupported(e, "optional call");
    for (const a of e.arguments) if (a.type === "SpreadElement") this.unsupported(e, "spread args");
    if (e.callee.type === "MemberExpression") {
      // method call: [this, fn, args...] then CALL_METHOD
      const m = e.callee;
      this.compileExpr(fn, m.object);   // this
      fn.emit(OP.DUP);                  // this, this
      if (m.computed) { this.compileExpr(fn, m.property); fn.emit(OP.GET_PROP); }
      else fn.emit(OP.GET_PROP_C, this.constIndex(m.property.name)); // this, fn
      for (const a of e.arguments) this.compileExpr(fn, a);
      fn.emit(OP.CALL_METHOD, e.arguments.length);
    } else {
      this.compileExpr(fn, e.callee);   // fn
      for (const a of e.arguments) this.compileExpr(fn, a);
      fn.emit(OP.CALL, e.arguments.length);
    }
  }

  // Push the current value of an identifier (local slot, upvalue, or global). Shared by
  // the Identifier expression case and the compound-assign / update read paths.
  emitLoadIdent(fn, name) {
    if (name === "undefined") return void fn.emit(OP.PUSH_UNDEF);
    const r = this.resolve(fn, name);
    if (!r) return void fn.emit(OP.LOAD_GLOBAL, this.nameIndex(name));
    r.hops === 0 ? fn.emit(OP.LOAD, r.slot) : fn.emit(OP.LOAD_UP, r.hops, r.slot);
  }

  // lvalue store: returns emit fns that consume the value already on stack.
  storeIdent(fn, name) {
    const r = this.resolve(fn, name);
    if (!r) this.unsupported({}, "assignment to undeclared '" + name + "'");
    if (r.hops === 0) fn.emit(OP.STORE, r.slot);
    else fn.emit(OP.STORE_UP, r.hops, r.slot);
  }

  compileAssign(fn, e) {
    const op = e.operator;
    const t = e.left;
    if (t.type === "Identifier") {
      if (op === "=") {
        this.compileExpr(fn, e.right);
        fn.emit(OP.DUP);       // leave value as expression result
        this.storeIdent(fn, t.name);
        return;
      }
      // compound: load, op, dup, store
      this.emitLoadIdent(fn, t.name);
      this.compileExpr(fn, e.right);
      fn.emit(this.compoundOp(e, op));
      fn.emit(OP.DUP);
      this.storeIdent(fn, t.name);
      return;
    }
    if (t.type === "MemberExpression") {
      if (t.computed) {
        if (op !== "=") this.unsupported(e, "computed compound assignment");
        this.compileExpr(fn, t.object);
        this.compileExpr(fn, t.property);
        this.compileExpr(fn, e.right);
        fn.emit(OP.SET_PROP); // leaves value
        return;
      }
      const keyIdx = this.constIndex(t.property.name);
      if (op === "=") {
        this.compileExpr(fn, t.object);
        this.compileExpr(fn, e.right);
        fn.emit(OP.SET_PROP_C, keyIdx); // leaves value
        return;
      }
      // o.p += v : [o]; DUP; GET_PROP_C; v; op; SET_PROP_C
      this.compileExpr(fn, t.object);
      fn.emit(OP.DUP);
      fn.emit(OP.GET_PROP_C, keyIdx);
      this.compileExpr(fn, e.right);
      fn.emit(this.compoundOp(e, op));
      fn.emit(OP.SET_PROP_C, keyIdx);
      return;
    }
    this.unsupported(e, "assignment target " + t.type);
  }
  compoundOp(e, op) {
    if (!(op in COMPOUND_OP)) this.unsupported(e, "compound op " + op);
    return COMPOUND_OP[op];
  }

  compileUpdate(fn, e) {
    // ++/-- always coerce their operand to a Number first (ToNumber), so we UPLUS the
    // loaded value before applying the delta — otherwise `s++` on a string would
    // concatenate ("5"+1 = "51") instead of incrementing. The delta itself is +1/-1.
    const t = e.argument;
    const one = () => fn.emit(OP.PUSH_CONST, this.constIndex(1));
    const delta = e.operator === "++" ? OP.ADD : OP.SUB;
    // postfix must yield the *old* numeric value; recover it from the stored new value by
    // undoing the delta (new - 1 for ++, new + 1 for --).
    const undelta = e.operator === "++" ? OP.SUB : OP.ADD;
    if (t.type === "Identifier") {
      this.emitLoadIdent(fn, t.name);
      fn.emit(OP.UPLUS); // ToNumber(old)
      if (e.prefix) { one(); fn.emit(delta); fn.emit(OP.DUP); this.storeIdent(fn, t.name); }
      else { fn.emit(OP.DUP); one(); fn.emit(delta); this.storeIdent(fn, t.name); } // leaves old
      return;
    }
    if (t.type === "MemberExpression" && !t.computed) {
      const keyIdx = this.constIndex(t.property.name);
      this.compileExpr(fn, t.object); // [o]
      fn.emit(OP.DUP);                // [o,o]
      fn.emit(OP.GET_PROP_C, keyIdx); // [o, old]
      fn.emit(OP.UPLUS);              // [o, ToNumber(old)]
      one(); fn.emit(delta);          // [o, new]
      fn.emit(OP.SET_PROP_C, keyIdx); // side effect applied; leaves [new]
      if (!e.prefix) { one(); fn.emit(undelta); } // postfix: [new] -> [old]
      return;
    }
    // Computed member (o[k]++) would need the object and key evaluated once but reachable
    // twice; the stack machine has no SWAP, so we don't risk a double-eval. Use prefix on a
    // simple member or an explicit `o[k] = o[k] + 1` form instead.
    this.unsupported(e, "update on computed member");
  }

  unsupported(node, what) {
    const where = node && node.start != null ? ` (at offset ${node.start})` : "";
    throw new Error(`brittle jsc: unsupported ${what}${where}`);
  }
}

// Jump opcodes whose single operand is an instruction index that must be relocated to a
// flat-code word offset when we linearize.
const JUMP_OPS = new Set([OP.JMP, OP.JMP_IF_FALSE, OP.JMP_IF_TRUE]);

// Pack a proto's variable-length instruction tuples (number[][], convenient to emit and
// backpatch) into one flat Int32Array laid out [op, ...operands, op, ...]. A flat typed
// array lets the engine dispatch loop read opcodes/operands with monomorphic integer indexing
// instead of chasing a pointer to a sub-array per instruction.
//
// Jump targets were stored by the compiler as INSTRUCTION indices; here we rewrite each to
// the WORD offset where that instruction begins. `offsets` carries one extra slot so a
// jump to here()==code.length (one past the last instruction) maps to the end of the flat
// array and the run loop terminates cleanly.
function linearize(proto) {
  const src = proto.code;
  const offsets = new Array(src.length + 1);
  let pos = 0;
  for (let i = 0; i < src.length; i++) {
    offsets[i] = pos;
    pos += src[i].length;
  }
  offsets[src.length] = pos;
  const flat = new Int32Array(pos);
  let w = 0;
  for (const ins of src) {
    flat[w++] = ins[0];
    const relocate = JUMP_OPS.has(ins[0]);
    for (let k = 1; k < ins.length; k++) flat[w++] = relocate && k === 1 ? offsets[ins[k]] : ins[k];
  }
  proto.code = flat;
}

// Locate the single function to virtualize from a source string.
function locateFunction(ast) {
  for (const n of ast.body) {
    if (n.type === "FunctionDeclaration") return n;
    if (n.type === "ExpressionStatement") {
      const x = n.expression;
      if (x.type === "FunctionExpression" || x.type === "ArrowFunctionExpression") return x;
    }
    if (n.type === "VariableDeclaration") {
      for (const d of n.declarations) {
        if (d.init && (d.init.type === "FunctionExpression" || d.init.type === "ArrowFunctionExpression")) return d.init;
      }
    }
  }
  return null;
}

// Public: compile a source string containing one function -> module for src/jsvm/vm.js.
// The located function becomes functions[entry]; nested functions/closures follow.
export function compileFunctionSource(source) {
  let ast;
  try {
    ast = parse(source, { ecmaVersion: 2022 });
  } catch {
    // allow a bare anonymous function expression, e.g. "function(a){...}" or "(a)=>a"
    ast = parse(`(${source})`, { ecmaVersion: 2022 });
  }
  const target = locateFunction(ast);
  if (!target) throw new Error("brittle jsc: no function found to virtualize");
  const c = new Compiler();
  const entry = c.compileFn(target, null);
  for (const proto of c.functions) linearize(proto); // tuples -> flat Int32Array bytecode
  return { consts: c.consts, names: c.names, functions: c.functions, entry };
}
