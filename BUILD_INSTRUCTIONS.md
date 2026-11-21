# Cyber Hub Manager — Build on GitHub Actions

This repository is set up for automatic APK builds.

## Current status

- GitHub Actions workflow is present: `.github/workflows/build-apk.yml`
- Core Gradle files, tools/dependencies.py, AndroidManifest and resources are in the repo.
- The large binary JARs, native .so files, CodeMirror full sources, and the original development keystore are **not** committed (they are regenerable or large).

## To make a perfect, error-free build

**You must push the complete source from your ZIP** (the Java sources, full assets including app.js / style.css / vendor, tools/build.py, etc.).

Run these commands on your computer with the original ZIP:

```bash
unzip Cyber-Hub-Manager.zip
cd Cyber-Hub-Manager

git init
git remote add origin https://github.com/yosatiktok9-bot/Cyber-Hub-Manager.git
git pull origin main --allow-unrelated-histories
# Keep the .gitignore that ignores app/libs and the p12 if asked

git add .
git commit -m "Complete source tree from original ZIP — ready for CI"
git push -u origin main
```

After the push, go to the **Actions** tab on GitHub and either:
- Wait for the automatic run, or
- Click "Build Cyber Hub Manager APK" → "Run workflow"

When it finishes successfully, download the artifact **Cyber-Hub-Manager-0.1.6**.

The workflow:
1. Installs JDK 17 + Android SDK 34 + build-tools 34.0.0
2. Runs `tools/dependencies.py` to fetch every JAR and the Zstd native libraries
3. Creates a matching development keystore
4. Runs the project’s own `tools/build.py` (the same builder you used for 3 months)
5. Uploads the signed, verified APK

This produces the same style of development APK you have been building locally.
