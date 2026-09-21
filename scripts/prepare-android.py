#!/usr/bin/env python3
"""Overlay reviewed Android sources onto the reproducible Tauri generated shell."""
from pathlib import Path
import shutil
import hashlib
import json
import re

root = Path(__file__).resolve().parents[1]
source = root / 'apps/desktop/android'
project = root / 'apps/desktop/src-tauri/gen/android'
assert (project / 'app/build.gradle.kts').exists(), 'Run pnpm tauri android init first'
# Removed overlay class: Java avoids a Kotlin dependency in the standalone test APK.
(project / 'app/src/androidTest/java/org/sirinvpn/client/CatalogActivity.kt').unlink(missing_ok=True)
shutil.copytree(source / 'src', project / 'app/src', dirs_exist_ok=True)
shutil.copyfile(source / 'proguard-rules.pro', project / 'app/proguard-rules.pro')
payloads = project / 'app/src/main/assets/server-payloads'
payloads.mkdir(parents=True, exist_ok=True)
digests = {}
for arch in ('x86_64', 'aarch64'):
    artifact = root / f'target/server-payloads/{arch}-unknown-linux-gnu/release/sirinvpn-server'
    assert artifact.is_file(), 'Build VPS payloads with packaging/Dockerfile.server-payloads first'
    destination = payloads / arch / 'sirinvpn-server'
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(artifact, destination)
    digests[arch] = hashlib.sha256(artifact.read_bytes()).hexdigest()
(payloads / 'sha256.json').write_text(json.dumps(digests))
gradle = project / 'app/build.gradle.kts'
text = gradle.read_text().replace('minSdk = 24', 'minSdk = 29').replace('jvmTarget = "1.8"', 'jvmTarget = "17"')
if 'ndkVersion =' not in text:
    text = text.replace('    compileSdk = 36','    compileSdk = 36\n    ndkVersion = "30.0.16248370"')
# Keep native symbols in target/ for debugging, not in every installed development APK.
text = re.sub(r'jniLibs\.keepDebugSymbols\.add\("[^\"]+"\)', '', text).replace('isJniDebuggable = true','isJniDebuggable = false')
if 'SIRIN_ANDROID_ABIS' not in text:
    text = text.replace('    defaultConfig {', '    defaultConfig {\n        ndk { abiFilters.addAll((System.getenv("SIRIN_ANDROID_ABIS") ?: "arm64-v8a,x86_64").split(",")) }')
if 'testInstrumentationRunner =' not in text:
    text = text.replace('    defaultConfig {','    defaultConfig {\n        testInstrumentationRunner = "androidx.test.runner.AndroidJUnitRunner"')
if 'zxing-android-embedded' not in text:
    text = text.replace('dependencies {','dependencies {\n    implementation("com.journeyapps:zxing-android-embedded:4.3.0")')
text = text.replace('buildConfig = true', 'buildConfig = true\n        aidl = true') if 'aidl = true' not in text else text
if 'sourceCompatibility' not in text:
    text = text.replace('    kotlinOptions {', '    compileOptions {\n        sourceCompatibility = JavaVersion.VERSION_17\n        targetCompatibility = JavaVersion.VERSION_17\n    }\n    kotlinOptions {')
gradle.write_text(text)
print('Android shell prepared from tracked sources')
