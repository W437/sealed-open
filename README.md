# sealed-open: open a Sealed vault without Sealed

If Sealed disappears tomorrow, your vault still opens. Sealed keeps an **open copy** of the vault in your iCloud Drive (the folder
named Sealed; Settings → Open Without Sealed), and can export the same copy to Files, a drive or a computer. These two readers open
that copy with the vault's **recovery key** and nothing else: no account, no network, no Sealed app, no server of ours.

| File | What it is |
|---|---|
| `sealed-open.py` | A single-file Python 3 program (3.8 or newer). Needs only the `cryptography` package. |
| `sealed-open.html` | One self-contained web page. Open it in a browser (Chrome, Edge, Firefox or Safari on a computer), offline. Its own security policy forbids every network connection; it decrypts with the browser's WebCrypto. |

Both readers travel inside every copy Sealed writes, so the copy carries its own way out.

## Run it

```sh
python3 -m pip install cryptography
python3 sealed-open.py "Sealed Vault.sealedvault" "Opened vault"
```

It asks for the recovery key (what you type is not shown), says whether the key opens this vault, then writes:

- every photo, video, document and voice memo as an ordinary file with its original name, dated as it was taken;
- stacks as folders (sub-stacks inside them); things in no stack at the top;
- each note as a `.txt`, plus `.rtf` (or an `.rtfd` folder, when it has pictures) for its formatting;
- each record (logins, cards, Wi-Fi, …) as a `.txt`, and all records together in `Records.json`;
- `Report.txt`: the counts and anything it could not open.

`--report-json FILE` also writes the list of files as JSON; `--phrase-stdin` reads the key from standard input (for scripts).

The web page does the same: choose the `.sealedvault` folder (or a .zip of it: phones cannot pick a folder, so zip it first), type
the key, press Open, then **Save into a folder…** (Chrome and Edge) or **Download everything (.zip)**. A single .zip made by a
browser is limited to 4 GB; for a larger vault use the folder, or the Python reader.

## What it tells you

- **"The recovery key opens this vault"**: checked against the copy's key check before anything is decrypted.
- **"This recovery key is not this vault's"**: another vault's key, or (for a key of 12 groups) one that was replaced.
- **Only in the iCloud backup**: items Space Saver kept only in Sealed's iCloud backup; the copy lists them but cannot include them.
- **Missing**: listed but not in this copy (iCloud Drive may still be downloading it to this computer: open the folder in Finder
  and wait, or choose "Download Now").

## The format

Both readers follow Sealed's encryption specification ("Sealed: encryption and key handling": the open copy's section with the
key check, the file format, the recovery key and the JSON inside a sealed value), which is published with its test vectors when
the version of Sealed that writes these copies is released.

## License

MIT License

Copyright (c) 2026 Loopware

Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the
"Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge,
publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so,
subject to the following conditions:

The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR
ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
