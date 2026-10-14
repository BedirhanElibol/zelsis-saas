/**
 * When Java / Kotlin ObjectInputStream use cannot load attacker-chosen classes, shared by CORE-03 and JAVA-SEC-03.
 * Measured on NewPipe (2026-10-14): its settings import reads through an allowlisting subclass, and its other
 * readObject calls deserialize bytes the app produced itself, yet both rules reported CRITICAL.
 */

/** Every ObjectInputStream built in the file: the class name and the argument text. */
function constructions(content: string): { cls: string; arg: string }[] {
  return [...content.matchAll(/(?:\bnew\s+)?\b(\w*ObjectInputStream)\s*\(([^;]{0,240})/g)].map((m) => ({ cls: m[1], arg: m[2] }));
}

export function javaDeserializationIsSafe(content: string): boolean {
  // An allowlist (resolveClass override) or a JEP 290 / commons-io filter guards the stream
  if (/\bresolveClass\s*\(|\bObjectInputFilter\b|setObjectInputFilter|ValidatingObjectInputStream|LookAheadObjectInputStream/.test(content)) return true;
  const built = constructions(content).filter((c) => !/^(?:class|extends)$/.test(c.cls));
  if (built.length === 0) return false;
  const android = /^\s*import\s+android\./m.test(content);
  return built.every((c) =>
    // A project subclass (the plain JDK class is the unsafe one)
    c.cls !== 'ObjectInputStream'
    // Deep copy: the stream reads ByteArrayOutputStream.toByteArray() of bytes this code just wrote with writeObject
    // (bytes decoded from a string or request are not a copy: WebGoat SerializationHelper.fromString)
    || (/ByteArrayInputStream\s*\(\s*\w+\.toByteArray\s*\(\s*\)/.test(c.arg) && /\bByteArrayOutputStream\b/.test(content) && /\.writeObject\s*\(/.test(content))
    // Android: a file in the app's private storage that only this app can write
    || (android && readsLocalFile(c.arg, content)));
}

/** The argument is a FileInputStream / openFileInput call, or a variable assigned from one in the same file. */
function readsLocalFile(arg: string, content: string): boolean {
  if (/\b(?:FileInputStream|openFileInput)\b/.test(arg)) return true;
  const id = arg.match(/^\s*(\w+)\s*\)/)?.[1];
  return Boolean(id && new RegExp(String.raw`\b${id}\s*(?::\s*[\w.?]+)?\s*=\s*(?:new\s+)?(?:FileInputStream|\w+\.openFileInput|openFileInput)\s*\(`).test(content));
}
