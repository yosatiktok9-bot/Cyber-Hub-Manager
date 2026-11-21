# Cyber Hub Manager — power-up plan

Goal: grow the app toward MT-Manager-class tooling. Six features, implemented in
order, each shippable on its own. This file is the working plan; it is not part of
the app package.

Environment note: this session has no JDK/Gradle/Android SDK/Python/Node, so I edit
and syntax-check source only. You build the APK (`bash gradlew assembleDebug` or
`python tools/build.py --sdk ...`).

## Shared conventions (used by every feature)

- Native entry point: add a `case` in `DataEngine.call(...)`. The UI already routes
  unknown actions there, so no bridge changes are needed for pure file/DEX work.
- UI entry point: a `toolPage(title, subtitle)` screen for full-page tools, or
  `dialog()/options()/ask()/confirmBox()` for focused flows.
- Errors: throw `IOException("...")` in Java. The bridge shows the message; the UI
  never sees a stack trace.
- Files: always publish atomically. Use `FileOps.writeAtomic` / `FileOps.replace`
  and, for traces that overwrite a source (APK/DEX/ARSC/binary), keep a backup with
  `FileOps.commitWithBackup` exactly like the DEX commit path does.
- Path safety: never accept a raw path from the UI for a new location without the
  `FileOps.child` / `FileOps.contained` checks.
- Long work runs on the existing `worker` thread pool; keep a single job at a time
  for destructive operations, like `bundleJob`.

---

## 1. Custom keystore signing (do first, smallest blast radius)

Status: DONE (pending your build/test). Implemented as: new `KeystoreStore.java`
(private `filesDir/keys/`, prefs Base64 password + index + default); `ApkSigning`
gained a detached `Credential` plus `fromStream`/`from` builders and a
`sign(File,File,Credential)` core (V1/V2/V3 verify + atomic publish kept); the old
`sign(File,File,InputStream)` dev-key overload is kept and now delegates to it.
`DexEngine.commit` takes a `Credential` (tests updated). `DataEngine` gained
`keys`, `keyImport`, `keyDefault`, `keyDelete`; the existing `sign` action takes an
optional `key` name. UI: Key Store page in the drawer and a keystore chooser in
`showApk`/"Sign file". Deviation from the sketch below: signing uses the detached
`Credential` (not a raw `KeyStore`) so `DexEngine` stays Android-free for the JVM
tests; JKS is tried but usually fails on Android, BKS is unsupported — both give a
clear "convert to PKCS12" message.

Problem: `ApkSigning.sign` hardcodes the bundled dev PKCS12 and a fixed password.
There is no way to sign with the user's own key, which is the most-requested MT
feature.

Native
- New `KeystoreStore.java`: holds a copy of an imported keystore under
  `getFilesDir()/keys/`, its type (JKS/PKCS12/BKS), and a stored password in
  `EncryptedSharedPreferences`/`androidx.security` is **not** available here, so use
  the app's private prefs and document that it is not hardware-backed.
  - `importKey(srcFile, password)` → verify it loads, list `alias`, `validity`,
    `subject`, `sha256`, copy the file into the private dir.
  - `keyStore()` → a loaded `KeyStore` + alias + password for signing.
  - `deleteKey(name)`.
- `ApkSigning`: add
  `sign(File src, File dst, KeyStore store, String alias, char[] password)` and keep
  the existing dev-key overload delegating to it. Preserve the mandatory V1/V2/V3
  verify and atomic publish.
- `DataEngine`: `keys` (list), `keyImport` (path/password/name), `keyDelete`,
  `keySign` (src/destination/keystore name/alias → sign a copy). Route the existing
  `sign` action through the selected keystore when one is configured.

UI
- Drawer "Tools" gets a **Key Store** page: import (path + password + name),
  list keystores with alias/SHA-256/expiry, delete, and "set as default signer".
- `showApk` → "Sign a copy" gets a keystore chooser instead of always using the dev key.
- Keep the dev-key wording; add "using your imported key" when applicable.

Risks: password storage is only as strong as app-private storage; call this out in
the UI. JKS/BKS need the matching `KeyStore` provider (JKS is present on Android;
BKS needs BouncyCastle — out of scope, reject clearly).

---

## 2. Resource (ARSC) editing

Problem: ARSC is view/filter/export only. ARSCLib 1.4.0 is already bundled.

Native
- New `ArscEdit.java` wrapping `ARSCLib` (`ResTable`/`ResTableParser`):
  - `open(File arsc, File apk)` → parse, return package/type/entry counts.
  - `entries(type, typeId, packageId, filter)` → list entries with key + values.
  - `editString(packageId, typeId, entryId, config, newValue)` → set a string value.
  - `save()` → encode and return bytes.
- Add a `guest` path mirroring `archiveEdits`: when `resources.arsc` was opened from
  an APK, saving records the new bytes and triggers the same `rewriteZip` +
  "needs signing" flow the manifest editor uses today.
- Actions: `arscOpen`, `arscEntries`, `arscSet`, `arscSave`.

UI
- Extend the existing String Pool page, or add an "Edit resources" action on
  `resources.arsc`: package/type tree, entry list, tap an entry to edit its string,
  Save. Editing flags the APK as needing a signature, reusing the existing dialog.

Risks: only string-value editing in v1. New resources / symbol resolution across
configs stay out of scope (already documented as a limit).

---

## 3. Hex editor

Status: DONE (pending your build/test). New `HexEdit.java` opens a 64 KB window,
pages, and patches in place with a `.bak` + atomic publish (no resize); `saveAs`
writes a patched copy for read-only sources. `DataEngine` gained `hexOpen`,
`hexPage`, `hexSave`, `hexSaveAs`. UI: a Hex Editor drawer page (offset column,
hex + ASCII, PREV/NEXT/GO TO/EDIT/SAVE/SAVE COPY), opened from the file menu's
Open with..., and `.hexgrid` styles in `style.css`. Helpers used from the existing
`size()/esc()/date()`.

Native
- New `HexEdit.java`: `open(path, offset)` → bytes + length; `write(path, offset,
  bytes)` → overwrite in place atomically with a `.bak`; refuse archive entries.
- Actions: `hexOpen`, `hexSave`, `hexSaveAs` (export a copy).

UI
- A `toolPage` hex view: offset column, 16 bytes hex, ASCII gutter, paging with
  prev/next, a "goto offset" box, and an edit mode that patches the selected bytes.
  Save is disabled for read-only sources.

Risks: large files must page, not load whole. Cap the window (e.g. 64 KB/page).

---

## 4. DEX rename (class / method / field)

Approach that reuses proven code: rename by re-emitting **smali** for the affected
classes and reassembling, then rebuilding only the owner DEX files exactly like
`DexEngine.applyClasses` already does (no new `DexPool` calls needed).

Native (`DexEngine`)
- `renameClass(oldType, newType)`, `renameMethod(type, name, desc, newName)`,
  `renameField(type, name, fieldType, newName)`.
- Find references with `DexQueries.uses(...)` (already implemented), collect the
  set of classes whose smali must change, produce updated smali text, assemble each
  with `Smali.assemble`, then rebuild the affected owner DEX files with
  `DexPool.writeTo` inside the existing transactional publish (staged files +
  backups + rollback).
- Guard: reject renames that would collide or leave dangling references; reject
  renames that cross an untouched DEX the user did not load (report which file).

UI
- In the member navigation long-press menu (`navigationOptions`), add **Rename**.
  A small dialog takes the new simple name; show a preview of affected classes and
  a count of rewritten references before applying. It updates the in-memory project,
  not the source; the existing Save/Save-and-sign flow publishes.

Risks: renaming across DEX files that are not all loaded is not safe — either load
all, or restrict the rename to references inside the loaded set and warn. Note
that reflection/string references cannot be renamed.

---

## 5. Root file access (optional, only if `su` is present)

Native
- New `RootShell.java`: locate `su` (`/system/bin/su`, `/system/xbin/su`, `which su`),
  confirm interactive grant once, then run `ls/cat/cp/rm` via `su -c`. Nothing is
  attempted when no `su` binary exists — the UI simply does not offer it.
- `DataEngine`: `rootAvailable`, and a `root` action namespace (`list`, `read`,
  `write`, `copy`, `delete`) guarded by containment checks on absolute paths.

UI
- A toggle in Preferences ("Show root paths when available"). When on, the file
  manager can browse `/` and mark root-only rows. All destructive root actions use
  the existing confirm flow.

Risks: device-specific; cannot be tested here. Keep it strictly opt-in and inert
when unrooted. This is the riskiest item and can be cut without affecting the rest.

---

## 6. More network clients

Status: PARTIAL — WebDAV DONE (pending your build/test). New `WebDavTools.java`
(java.net only, no new jars): PROPFIND listing, GET download, PUT upload, Basic
auth, DOCTYPE disabled. Routed via the existing `ftp` action when `protocol` is
`webdav` (plain `ftp` now forces `tls=false`). UI: `ftpPage` gained a protocol
selector (FTPS/FTP/WebDAV) and the drawer row now reads "FTP / FTPS / WebDAV".
SFTP is still NOT implemented (needs a bundled SSH library).

Native
- Add SFTP (Apache MINA sshd or sshj) and WebDAV (own PROPFIND/GET/PUT) alongside the
  existing FTP via a shared `RemoteClient` interface: `list(remote)`, `download`,
  `upload`, `delete`, `mkdir`. Wire into the already-present `ftp` action so the FTP
  page becomes a general "Network connection" page with a protocol selector.

UI
- Extend `ftpPage` with a protocol dropdown (FTP/FTPS/SFTP/WebDAV), host/port/user/
  password/key fields, and reuse `ftpBrowse` for all protocols.

Risks: new JARs must be added to `app/libs/` and `tools/dependencies.py`; they also
have to be dexed into the APK by the fallback builder. Verify they dex cleanly.

## 7. Protection & signer inspection (added by request)

Status: DONE (pending your build/test). New `Protection.java` fingerprints common
packers (360, Legu, Bangcle, Najia, Ijiami, Ali/《mPaaS》, DexProtector, Virbox)
from archive entry names, flags assets-embedded DEX and MultiDex, and reports the
real signer certificates (subject/issuer/algorithm/expiry/SHA-256) via
`ApkVerifier.Result.getSignerCertificates()`. `apkInfo` now includes `protection`;
`showApk` shows the packer list (replacing the old "Not assessed" stub) plus a
"Protection report" dialog. Heuristics are explicitly labelled best-effort.
NOT included: signature verification removal / core patch — genuinely risky, needs
its own careful pass.

---

## Verification plan

- Source-level: `diagnostics` on each edited Java/JS/JSON/XML file after edits.
- Structural: re-read every changed function and its callers (I do this each pass).
- On your side: build with Gradle (or `tools/build.py`), then run the JVM tests that
  already exist (`tests/run-core.py`, `ApkSmokeTest`, `JavaFlowSmokeTest`) once a
  JDK is available, and exercise signing/ARSC/rename on a real APK on-device.
- Cannot verify here: compilation, DEX assembly, signing, ARSC round-trip, root.
  These need the JDK + a device, which this session does not have.

## Order & checkpoints

1. Keystore signing — checkpoint: sign an APK with an imported key, verify V1/V2/V3.
2. ARSC editing — checkpoint: edit one string, rebuild the APK, confirm it launches.
3. Hex editor — checkpoint: patch a byte, re-open, confirm.
4. DEX rename — checkpoint: rename a class in a throwaway APK, confirm it loads.
5. Root — checkpoint: browse `/data/local/tmp` on a rooted device.
6. Network clients — checkpoint: list/download over SFTP and WebDAV.

I will implement one feature per pass and stop for your build/test at each checkpoint.
