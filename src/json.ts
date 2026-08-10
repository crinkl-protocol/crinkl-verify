export type JsonValue = null | boolean | number | string | readonly JsonValue[] | { readonly [key: string]: JsonValue };

export interface JsonSnapshot {
  value?: JsonValue;
  error?: string;
}

function hasUnpairedSurrogate(value: string): boolean {
  for (let index = 0; index < value.length; index += 1) {
    const codeUnit = value.charCodeAt(index);
    if (codeUnit >= 0xd800 && codeUnit <= 0xdbff) {
      const next = value.charCodeAt(index + 1);
      if (!(next >= 0xdc00 && next <= 0xdfff)) return true;
      index += 1;
    } else if (codeUnit >= 0xdc00 && codeUnit <= 0xdfff) {
      return true;
    }
  }
  return false;
}

function invalid(path: string, message: string): JsonSnapshot {
  return { error: `${path}: ${message}` };
}

/**
 * Copies an input JSON tree without invoking user accessors and freezes every
 * copied container. Verification uses this snapshot exclusively so a caller
 * cannot alter the signed view between validation, hashing, and policy checks.
 *
 * The descriptor pass deliberately precedes the `structuredClone` proxy
 * screen: standard structured cloning reads enumerable getters, while this
 * verifier must reject accessors without invoking them. `structuredClone` is
 * used only to reject otherwise-transparent Proxies after the inert snapshot
 * has been made; its output is never trusted or used for verification.
 */
export function createInertJsonSnapshot(input: unknown): JsonSnapshot {
  const seen = new WeakSet<object>();

  function copy(value: unknown, path: string): JsonSnapshot {
    if (value === null || typeof value === "boolean") return { value };
    if (typeof value === "string") {
      return hasUnpairedSurrogate(value)
        ? invalid(path, "strings must not contain unpaired UTF-16 surrogates")
        : { value };
    }
    if (typeof value === "number") {
      return Number.isFinite(value) ? { value } : invalid(path, "numbers must be finite");
    }
    if (typeof value !== "object") return invalid(path, `unsupported JSON value type ${typeof value}`);
    if (seen.has(value)) return invalid(path, "cycles and shared object references are not JSON values");
    seen.add(value);

    if (Array.isArray(value)) {
      if (Object.getPrototypeOf(value) !== Array.prototype) return invalid(path, "arrays must have the standard prototype");
      const keys = Reflect.ownKeys(value);
      if (keys.some((key) => typeof key !== "string")) return invalid(path, "symbol properties are not JSON values");
      const names = keys as string[];
      if (names.some((key) => key !== "length" && !/^(0|[1-9][0-9]*)$/.test(key))) return invalid(path, "arrays must not contain non-index properties");
      const result: JsonValue[] = [];
      for (let index = 0; index < value.length; index += 1) {
        const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
        if (!descriptor) return invalid(path, "sparse arrays are not JSON values");
        if (!("value" in descriptor) || !descriptor.enumerable) return invalid(`${path}[${index}]`, "array elements must be enumerable data properties");
        const child = copy(descriptor.value, `${path}[${index}]`);
        if (child.error) return child;
        result.push(child.value as JsonValue);
      }
      return { value: Object.freeze(result) };
    }

    if (Object.getPrototypeOf(value) !== Object.prototype) return invalid(path, "objects must have the standard prototype");
    const keys = Reflect.ownKeys(value);
    if (keys.some((key) => typeof key !== "string")) return invalid(path, "symbol properties are not JSON values");
    const result: { [key: string]: JsonValue } = Object.create(null) as { [key: string]: JsonValue };
    for (const key of keys as string[]) {
      if (hasUnpairedSurrogate(key)) return invalid(path, "object keys must not contain unpaired UTF-16 surrogates");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      if (!descriptor || !("value" in descriptor) || !descriptor.enumerable) return invalid(`${path}.${key}`, "object properties must be enumerable data properties");
      const child = copy(descriptor.value, `${path}.${key}`);
      if (child.error) return child;
      Object.defineProperty(result, key, {
        value: child.value,
        enumerable: true,
        configurable: false,
        writable: false
      });
    }
    return { value: Object.freeze(result) };
  }

  let snapshot: JsonSnapshot;
  try {
    snapshot = copy(input, "$");
  } catch {
    return invalid("$", "objects must be inert JSON data containers");
  }
  if (snapshot.error || input === null || typeof input !== "object") return snapshot;

  try {
    // Proxies are not structured-cloneable. This final screen catches a
    // transparent Proxy which can otherwise imitate a plain data object to
    // the descriptor-only walk above. Do not use the cloned value: the inert
    // descriptor copy is the sole verification input.
    structuredClone(input);
  } catch {
    return invalid("$", "proxies are not JSON values");
  }

  return snapshot;
}
