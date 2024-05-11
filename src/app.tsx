import { useEffect, useMemo, useState } from "preact/hooks";
import nacl from "tweetnacl";
import { Encoder } from "cbor-x";

const explanation = `This is a simple editor that stores its content in 0pw.me, encrypted end-to-end.\nIf you lose the passphrase, the content is lost forever.`;

const subtle = window.crypto.subtle;

const encoder = new Encoder();

const backend =
  window.location.host == "1pw.me"
    ? "https://0pw.me"
    : `https://${window.location.host}/test`;

export function App() {
  const [error, setError] = useState<string | null>(null);
  const [passphrase, setPassphrase] = useState<string | null>(null);
  const [content, setContent] = useState<string | null>(null);
  const [working, setWorking] = useState<boolean>(false);
  const [seed, setSeed] = useState<Uint8Array | null>(null);

  const message = useMemo(
    () => new TextEncoder().encode(content || ""),
    [content],
  );
  const length = message.length;
  const lengthError = length > 64000;

  useEffect(() => {
    setWorking(true);
    (async () => {
      const key = await subtle.importKey(
        "raw",
        new TextEncoder().encode(passphrase || ""),
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
  }, [passphrase]);

  return (
    <div class="editor">
      <h1>🔏 1pw.me — passphrase → page</h1>
      <div>
        <input
          type="password"
          placeholder="Passphrase"
          value={passphrase || ""}
          onInput={(e) => setPassphrase((e.target as HTMLInputElement).value)}
        />
        <button
          disabled={working}
          onClick={() => {
            setWorking(true);
            (async () => {
              if (seed === null) {
                setError("No passphrase");
                return;
              }
              const signKP = nacl.sign.keyPair.fromSeed(seed);
              const boxKP = nacl.box.keyPair.fromSecretKey(seed);
              const postBytes = encoder.encode([signKP.publicKey]);
              const result = await fetch(backend, {
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
                setError("No passphrase");
                return;
              }
              const signKP = nacl.sign.keyPair.fromSeed(seed);
              const boxKP = nacl.box.keyPair.fromSecretKey(seed);
              const nonce = nacl.randomBytes(nacl.box.nonceLength);
              const box = nacl.secretbox(message, nonce, boxKP.secretKey);
              const payload = encoder.encode([nonce, box]);
              const signed = nacl.sign(payload, signKP.secretKey);
              const postBytes = encoder.encode([signKP.publicKey, signed]);
              const result = await fetch(backend, {
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
      <div class={(lengthError && "error") || undefined}>{length} / 64000</div>
    </div>
  );
}
