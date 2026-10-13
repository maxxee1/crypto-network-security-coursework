const pswd   = "Testing@6767";
const sal    = "gwcHzPbb-GS3MmiZEWD4MU3cFRVPL5nWeQNt_BVhmDE";
const iteraciones = 100000;

const fromB64url = (s) =>
  Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0));

const toB64url = (bytes) =>
  btoa(String.fromCharCode(...bytes)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

async function deriveUh(pswd, sal, iteraciones) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(pswd), "PBKDF2", false, ["deriveBits"]
  );

  const derived = new Uint8Array(
    await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: fromB64url(sal), iterations: iteraciones, hash: "SHA-512" }, // <-- aquí
      key, 256
    )
  );

  return toB64url(derived.slice(16, 32));
}
deriveUh(pswd, sal, iteraciones).then((uh) => console.log("uh =", uh));