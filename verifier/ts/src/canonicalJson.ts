export type JsonPrimitive = string | number | boolean | null;
export type JsonArray = JsonValue[];
export type JsonObject = { [key: string]: JsonValue };
export type JsonValue = JsonPrimitive | JsonArray | JsonObject;

export class DeltaCanonicalJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DeltaCanonicalJsonError";
  }
}

class StrictJsonParser {
  private index = 0;

  constructor(private readonly text: string) {}

  parse(): JsonValue {
    const value = this.parseValue();
    this.skipWhitespace();
    if (this.index !== this.text.length) {
      throw new DeltaCanonicalJsonError(`unexpected trailing content at offset ${this.index}`);
    }
    return value;
  }

  private current(): string | undefined {
    return this.text[this.index];
  }

  private skipWhitespace(): void {
    while (this.index < this.text.length && /\s/.test(this.text[this.index] ?? "")) {
      this.index += 1;
    }
  }

  private parseValue(): JsonValue {
    this.skipWhitespace();
    const ch = this.current();

    if (ch === "{") return this.parseObject();
    if (ch === "[") return this.parseArray();
    if (ch === '"') return this.parseString();
    if (ch === "t") return this.parseLiteral("true", true);
    if (ch === "f") return this.parseLiteral("false", false);
    if (ch === "n") return this.parseLiteral("null", null);
    if (ch === "-" || (ch !== undefined && ch >= "0" && ch <= "9")) return this.parseNumber();

    throw new DeltaCanonicalJsonError(`unexpected token at offset ${this.index}`);
  }

  private parseLiteral<T extends JsonValue>(literal: string, value: T): T {
    if (this.text.slice(this.index, this.index + literal.length) !== literal) {
      throw new DeltaCanonicalJsonError(`invalid literal at offset ${this.index}`);
    }
    this.index += literal.length;
    return value;
  }

  private parseString(): string {
    const start = this.index;
    this.index += 1;

    while (this.index < this.text.length) {
      const ch = this.text[this.index];

      if (ch === '"') {
        this.index += 1;
        const raw = this.text.slice(start, this.index);
        try {
          return JSON.parse(raw) as string;
        } catch (err) {
          throw new DeltaCanonicalJsonError(`invalid string at offset ${start}`);
        }
      }

      if (ch === "\\") {
        this.index += 1;
        const esc = this.text[this.index];
        if (esc === undefined) {
          throw new DeltaCanonicalJsonError(`unterminated escape at offset ${this.index}`);
        }
        if ('"\\/bfnrt'.includes(esc)) {
          this.index += 1;
          continue;
        }
        if (esc === "u") {
          const hex = this.text.slice(this.index + 1, this.index + 5);
          if (!/^[0-9a-fA-F]{4}$/.test(hex)) {
            throw new DeltaCanonicalJsonError(`invalid unicode escape at offset ${this.index}`);
          }
          this.index += 5;
          continue;
        }
        throw new DeltaCanonicalJsonError(`invalid escape at offset ${this.index}`);
      }

      const code = ch?.charCodeAt(0) ?? 0;
      if (code >= 0 && code <= 0x1f) {
        throw new DeltaCanonicalJsonError(`unescaped control character at offset ${this.index}`);
      }

      this.index += 1;
    }

    throw new DeltaCanonicalJsonError(`unterminated string at offset ${start}`);
  }

  private parseNumber(): number {
    const start = this.index;

    if (this.current() === "-") {
      this.index += 1;
    }

    const first = this.current();
    if (first === undefined) {
      throw new DeltaCanonicalJsonError(`invalid number at offset ${start}`);
    }

    if (first === "0") {
      this.index += 1;
      const next = this.current();
      if (next !== undefined && next >= "0" && next <= "9") {
        throw new DeltaCanonicalJsonError(`leading zero integer rejected at offset ${start}`);
      }
    } else if (first >= "1" && first <= "9") {
      while (this.current() !== undefined && (this.current()! >= "0" && this.current()! <= "9")) {
        this.index += 1;
      }
    } else {
      throw new DeltaCanonicalJsonError(`invalid number at offset ${start}`);
    }

    const next = this.current();
    if (next === "." || next === "e" || next === "E") {
      throw new DeltaCanonicalJsonError(`floating point numbers are rejected by DELTA profile at offset ${start}`);
    }

    const raw = this.text.slice(start, this.index);
    const value = Number(raw);

    if (!Number.isSafeInteger(value)) {
      throw new DeltaCanonicalJsonError(`unsafe integer rejected at offset ${start}`);
    }

    return Object.is(value, -0) ? 0 : value;
  }

  private parseArray(): JsonArray {
    this.index += 1;
    const values: JsonArray = [];
    this.skipWhitespace();

    if (this.current() === "]") {
      this.index += 1;
      return values;
    }

    while (true) {
      values.push(this.parseValue());
      this.skipWhitespace();

      const ch = this.current();
      if (ch === ",") {
        this.index += 1;
        continue;
      }
      if (ch === "]") {
        this.index += 1;
        return values;
      }

      throw new DeltaCanonicalJsonError(`expected comma or closing array at offset ${this.index}`);
    }
  }

  private parseObject(): JsonObject {
    this.index += 1;
    const obj: JsonObject = {};
    const seen = new Set<string>();
    this.skipWhitespace();

    if (this.current() === "}") {
      this.index += 1;
      return obj;
    }

    while (true) {
      this.skipWhitespace();
      if (this.current() !== '"') {
        throw new DeltaCanonicalJsonError(`object key must be a string at offset ${this.index}`);
      }

      const key = this.parseString();
      if (seen.has(key)) {
        throw new DeltaCanonicalJsonError(`duplicate object key rejected: ${key}`);
      }
      seen.add(key);

      this.skipWhitespace();
      if (this.current() !== ":") {
        throw new DeltaCanonicalJsonError(`expected colon after object key at offset ${this.index}`);
      }
      this.index += 1;

      obj[key] = this.parseValue();
      this.skipWhitespace();

      const ch = this.current();
      if (ch === ",") {
        this.index += 1;
        continue;
      }
      if (ch === "}") {
        this.index += 1;
        return obj;
      }

      throw new DeltaCanonicalJsonError(`expected comma or closing object at offset ${this.index}`);
    }
  }
}

export function parseStrictJson(text: string): JsonValue {
  return new StrictJsonParser(text).parse();
}

export function canonicalizeJsonText(text: string): string {
  return canonicalizeJsonValue(parseStrictJson(text));
}

export function canonicalizeJsonValue(value: JsonValue): string {
  if (value === null) return "null";

  if (typeof value === "boolean") {
    return value ? "true" : "false";
  }

  if (typeof value === "string") {
    return JSON.stringify(value);
  }

  if (typeof value === "number") {
    if (!Number.isSafeInteger(value)) {
      throw new DeltaCanonicalJsonError("only safe integers are allowed by DELTA profile");
    }
    return Object.is(value, -0) ? "0" : String(value);
  }

  if (Array.isArray(value)) {
    return `[${value.map((item) => canonicalizeJsonValue(item)).join(",")}]`;
  }

  const keys = Object.keys(value).sort();
  const parts = keys.map((key) => `${JSON.stringify(key)}:${canonicalizeJsonValue(value[key] as JsonValue)}`);
  return `{${parts.join(",")}}`;
}
