function bytes(data: string) {
  return Uint8Array.from(
    atob(data.replaceAll("-", "+").replaceAll("_", "/")),
    (c) => c.charCodeAt(0),
  );
}
function u32(n: number) {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n);
  return b;
}
function concat(...parts: Uint8Array[]) {
  const b = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    b.set(p, offset);
    offset += p.length;
  }
  return b;
}
const text = (s: string) => new TextEncoder().encode(s);
const field = (v: Uint8Array) => concat(u32(v.length), v);
function b64(v: Uint8Array) {
  return btoa(String.fromCharCode(...v));
}
export async function generateSSH() {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const jwk = await crypto.subtle.exportKey("jwk", pair.privateKey);
  if (!jwk.d || !jwk.x)
    throw new Error("Генерация Ed25519 не поддерживается браузером");
  const seed = bytes(jwk.d),
    pub = bytes(jwk.x);
  const type = text("ssh-ed25519");
  const publicBlob = concat(field(type), field(pub));
  const check = crypto.getRandomValues(new Uint8Array(4));
  let privateBlob = concat(
    check,
    check,
    field(type),
    field(pub),
    field(concat(seed, pub)),
    field(text("Heimdall browser key")),
  );
  const padding = 8 - (privateBlob.length % 8);
  privateBlob = concat(
    privateBlob,
    Uint8Array.from({ length: padding }, (_, i) => i + 1),
  );
  const content = concat(
    text("openssh-key-v1\0"),
    field(text("none")),
    field(text("none")),
    field(new Uint8Array()),
    u32(1),
    field(publicBlob),
    field(privateBlob),
  );
  const encoded = b64(content)
    .match(/.{1,70}/g)
    ?.join("\n");
  return {
    publicKey: `ssh-ed25519 ${b64(publicBlob)}`,
    privateKey: `-----BEGIN OPENSSH PRIVATE KEY-----\n${encoded}\n-----END OPENSSH PRIVATE KEY-----\n`,
  };
}
export function download(name: string, content: string) {
  const url = URL.createObjectURL(new Blob([content], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = name;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
