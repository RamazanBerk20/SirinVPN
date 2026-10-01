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
text = re.sub(r'jackson-bom:2\.18\.\d+', 'jackson-bom:2.18.11', text)
if 'jackson-bom:2.18.11' not in text:
    # Compatible 2.x maintenance line fixes advisories in Tauri's 2.15.3 dependency.
    text = text.replace('dependencies {', 'dependencies {\n    implementation(platform("com.fasterxml.jackson:jackson-bom:2.18.11"))')
text = text.replace('buildConfig = true', 'buildConfig = true\n        aidl = true') if 'aidl = true' not in text else text
if 'sourceCompatibility' not in text:
    text = text.replace('    kotlinOptions {', '    compileOptions {\n        sourceCompatibility = JavaVersion.VERSION_17\n        targetCompatibility = JavaVersion.VERSION_17\n    }\n    kotlinOptions {')
gradle.write_text(text)
lockfile = source / 'gradle.lockfile'
if lockfile.exists():
    shutil.copyfile(lockfile, project / 'app/gradle.lockfile')
if 'activateDependencyLocking()' not in text:
    text += '\nconfigurations.matching { it.name.endsWith("ReleaseRuntimeClasspath") }.configureEach {\n    resolutionStrategy.activateDependencyLocking()\n}\n'
    gradle.write_text(text)
properties = project / 'gradle.properties'
settings = properties.read_text().rstrip() + '\n'
if 'org.gradle.workers.max=' not in settings:
    settings += 'org.gradle.workers.max=2\n'
for key, value in [('org.gradle.daemon', 'false'), ('kotlin.compiler.execution.strategy', 'in-process')]:
    settings = re.sub(rf'(?m)^{re.escape(key)}=.*\n?', '', settings)
    settings += f'{key}={value}\n'
properties.write_text(settings)
print('Android shell prepared from tracked sources')
