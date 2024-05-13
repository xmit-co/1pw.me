import { useEffect, useMemo, useState } from "preact/hooks";
import nacl from "tweetnacl";
import { Encoder } from "cbor-x";

const explanation = `This editor stores its content encrypted end-to-end.\nIf you lose the password, the content is lost forever.`;
const maxLength = 65000;
const subtle = window.crypto.subtle;

const encoder = new Encoder();

export function App() {
  const [working, setWorking] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [pw, setPw] = useState<string | null>(null);
  const [seed, setSeed] = useState<Uint8Array | null>(null);
  const [content, setContent] = useState<string | null>(null);

  const message = useMemo(
    () => new TextEncoder().encode(content || ""),
    [content],
  );
  const length = message.length;
  const lengthError = length > maxLength;

  useEffect(() => {
    setWorking(true);
    (async () => {
      const key = await subtle.importKey(
        "raw",
        new TextEncoder().encode(pw || ""),
        "PBKDF2",
        false,
        ["deriveBits"],
      );
      const bits = await subtle.deriveBits(
        {
          name: "PBKDF2",
          hash: "SHA-256",
          salt: new TextEncoder().encode("1pw.me"),
          iterations: 100000,
        },
        key,
        256,
      );
      setSeed(new Uint8Array(bits));
      setWorking(false);
    })().catch((e) => {
      setError(e.message);
    });
  }, [pw]);

  return (
    <div class="editor">
      <h1>🔏 1pw.me — password → page</h1>
      <div>
        <input
          type="password"
          placeholder="Password"
          value={pw || ""}
          onInput={(e) => setPw((e.target as HTMLInputElement).value)}
        />
        <button
          disabled={working}
          onClick={() => {
            setWorking(true);
            (async () => {
              if (seed === null) {
                setError("No password");
                return;
              }
              const signKP = nacl.sign.keyPair.fromSeed(seed);
              const boxKP = nacl.box.keyPair.fromSecretKey(seed);
              const postBytes = encoder.encode([signKP.publicKey]);
              const result = await fetch("https://0pw.me", {
                method: "POST",
                body: postBytes,
              });
              if (!result.ok) {
                if (result.status === 404) {
                  setError("No such page");
                  return;
                }
                setError(`Request failed (${result.status})`);
                return;
              }
              const signed = await result.arrayBuffer();
              const payload = nacl.sign.open(
                new Uint8Array(signed),
                signKP.publicKey,
              );
              if (payload === null) {
                setError("Signature verification failed");
                return;
              }
              const [nonce, box] = encoder.decode(new Uint8Array(payload));
              const message = nacl.secretbox.open(box, nonce, boxKP.secretKey);
              if (message === null) {
                setError("Decryption failed");
                return;
              }
              setContent(new TextDecoder().decode(message));
              setError(null);
            })()
              .catch((e) => setError(e.message))
              .finally(() => {
                setWorking(false);
              });
          }}
        >
          Load
        </button>
        <button
          disabled={working || lengthError}
          onClick={() => {
            setWorking(true);
            (async () => {
              if (seed === null) {
                setError("No password");
                return;
              }
              const signKP = nacl.sign.keyPair.fromSeed(seed);
              const boxKP = nacl.box.keyPair.fromSecretKey(seed);
              const nonce = nacl.randomBytes(nacl.box.nonceLength);
              const box = nacl.secretbox(message, nonce, boxKP.secretKey);
              const payload = encoder.encode([nonce, box]);
              const signed = nacl.sign(payload, signKP.secretKey);
              const postBytes = encoder.encode([signKP.publicKey, signed]);
              const result = await fetch("https://0pw.me", {
                method: "POST",
                body: postBytes,
              });
              if (!result.ok) {
                setError(`${result.status} ${result.statusText}`);
              } else {
                setError(null);
              }
            })()
              .catch((e) => setError(e.message))
              .finally(() => {
                setWorking(false);
              });
          }}
        >
          Save
        </button>
        {error && <span class="error">{error}</span>}
      </div>
      <textarea
        value={content || ""}
        placeholder={explanation}
        onInput={(e) => setContent((e.target as HTMLTextAreaElement).value)}
      ></textarea>
      <footer>
        <div class={(lengthError && "error") || undefined}>
          {length} / {maxLength}
        </div>
        <div>
          powered by{" "}
          <a href="https://0pw.me" target="_blank">
            0pw.me
          </a>
          , a service by{" "}
          <a href="https://xmit.dev" target="_blank">
            xmit
          </a>
          ;{" "}
          <a
            href="https://github.com/xmit-co/1pw.me/blob/main/src/app.tsx"
            target="_blank"
          >
            open source
          </a>
        </div>
      </footer>
    </div>
  );
}
