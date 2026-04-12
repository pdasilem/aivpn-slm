#!/usr/bin/env bash
# build-rust-android.sh — cross-compile aivpn-android-core for all Android ABI targets
# and copy the resulting .so files into the app's jniLibs directory.
#
# Prerequisites:
#   cargo install cargo-ndk
#   rustup target add aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
#
# Optional release signing via keystore.properties in aivpn-android/:
#   storeFile=/absolute/path/to/release.jks
#   storePassword=...
#   keyAlias=...
#   keyPassword=...
#
# Or via environment variables:
#   export AIVPN_UPLOAD_STORE_FILE=/absolute/path/to/release.jks
#   export AIVPN_UPLOAD_STORE_PASSWORD=...
#   export AIVPN_UPLOAD_KEY_ALIAS=...
#   export AIVPN_UPLOAD_KEY_PASSWORD=...
#
# Usage:
#   cd aivpn-android
#   ./build-rust-android.sh            # debug build (default)
#   ./build-rust-android.sh release    # release build

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
JNI_LIBS_DIR="${SCRIPT_DIR}/app/src/main/jniLibs"
RELEASES_DIR="${REPO_ROOT}/releases"
APK_DST="${RELEASES_DIR}/aivpn-client.apk"

BUILD_TYPE="${1:-debug}"

pick_android_java_home() {
    if [[ -n "${AIVPN_ANDROID_JAVA_HOME:-}" ]]; then
        echo "${AIVPN_ANDROID_JAVA_HOME}"
        return 0
    fi

    if [[ -n "${JAVA_HOME:-}" ]]; then
        echo "${JAVA_HOME}"
        return 0
    fi

    if command -v /usr/libexec/java_home >/dev/null 2>&1; then
        for version in 21 17; do
            local candidate
            candidate="$(/usr/libexec/java_home -v "${version}" 2>/dev/null || true)"
            if [[ -n "${candidate}" && -x "${candidate}/bin/java" ]]; then
                echo "${candidate}"
                return 0
            fi
        done
    fi

    if command -v java >/dev/null 2>&1; then
        local java_bin
        java_bin="$(command -v java)"
        echo "$(cd "$(dirname "${java_bin}")/.." && pwd)"
        return 0
    fi

    return 1
}

if JAVA_HOME_SELECTED="$(pick_android_java_home)"; then
    export JAVA_HOME="${JAVA_HOME_SELECTED}"
    if [[ ":${PATH}:" != *":${JAVA_HOME}/bin:"* ]]; then
        export PATH="${PATH}:${JAVA_HOME}/bin"
    fi
else
    echo "ERROR: Java runtime not found. Install JDK 17 or JDK 21 and retry."
    exit 1
fi

echo "==> Building aivpn-android-core [${BUILD_TYPE}]"
echo "     Java: ${JAVA_HOME}"

# Require Android NDK
if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    # Common locations for NDK installed via Android Studio or command-line tools
    for candidate in \
        "${HOME}/Library/Android/sdk/ndk/latest" \
        "${HOME}/Library/Android/sdk/ndk/$(ls "${HOME}/Library/Android/sdk/ndk/" 2>/dev/null | sort -V | tail -1)" \
        "/usr/local/share/android-commandlinetools/ndk/latest" \
        "/opt/android-ndk"; do
        if [[ -d "${candidate}" ]]; then
            export ANDROID_NDK_HOME="${candidate}"
            break
        fi
    done
fi

if [[ -z "${ANDROID_NDK_HOME:-}" ]]; then
    echo "ERROR: ANDROID_NDK_HOME is not set and could not be auto-detected."
    echo "       Install the Android NDK and export ANDROID_NDK_HOME."
    exit 1
fi
echo "     NDK: ${ANDROID_NDK_HOME}"

# Confirm cargo-ndk is installed
if ! command -v cargo-ndk &>/dev/null; then
    echo "ERROR: cargo-ndk not found.  Run: cargo install cargo-ndk"
    exit 1
fi

RELEASE_FLAG=""
if [[ "${BUILD_TYPE}" == "release" ]]; then
    RELEASE_FLAG="--release"
fi

TARGETS=(
    "arm64-v8a:aarch64-linux-android"
    "armeabi-v7a:armv7-linux-androideabi"
    "x86_64:x86_64-linux-android"
)

pick_debug_abis() {
    if [[ -n "${AIVPN_ANDROID_ABIS:-}" ]]; then
        echo "${AIVPN_ANDROID_ABIS}"
        return 0
    fi

    if [[ "${BUILD_TYPE}" != "debug" ]]; then
        printf '%s\n' "arm64-v8a,armeabi-v7a,x86_64"
        return 0
    fi

    if command -v adb >/dev/null 2>&1; then
        local serial abi
        serial="$(adb devices | awk 'NR>1 && $2=="device" {print $1; exit}')"
        if [[ -n "${serial}" ]]; then
            abi="$(adb -s "${serial}" shell getprop ro.product.cpu.abi 2>/dev/null | tr -d '\r')"
            case "${abi}" in
                arm64-v8a|armeabi-v7a|x86_64)
                    echo "${abi}"
                    return 0
                    ;;
            esac
        fi
    fi

    echo "arm64-v8a"
}

SELECTED_ABIS="$(pick_debug_abis)"
IFS=',' read -r -a ABI_LIST <<< "${SELECTED_ABIS}"

declare -A ABI_MAP=(
    ["arm64-v8a"]="aarch64-linux-android"
    ["armeabi-v7a"]="armv7-linux-androideabi"
    ["x86_64"]="x86_64-linux-android"
)

for ABI in "${ABI_LIST[@]}"; do
    ABI="$(echo "${ABI}" | xargs)"
    TARGET_TRIPLE="${ABI_MAP[${ABI}]:-}"
    if [[ -z "${TARGET_TRIPLE}" ]]; then
        echo "ERROR: Unsupported ABI '${ABI}'. Supported: arm64-v8a, armeabi-v7a, x86_64"
        exit 1
    fi
    echo "--> [${ABI}]  cargo ndk -t ${ABI}"

    (
        cd "${REPO_ROOT}"
        cargo ndk \
            -t "${ABI}" \
            -o "${JNI_LIBS_DIR}" \
            -- build -p aivpn-android-core \
            ${RELEASE_FLAG}
    )

    echo "    Written to ${JNI_LIBS_DIR}/${ABI}/libaivpn_core.so"
done

echo ""
echo "==> Done.  .so files in ${JNI_LIBS_DIR}:"
find "${JNI_LIBS_DIR}" -name "libaivpn_core.so" -exec ls -lh {} \;

echo ""
echo "==> Building Android APK and publishing to releases/..."
mkdir -p "${RELEASES_DIR}"

if [[ "${BUILD_TYPE}" == "release" ]]; then
    if [[ -f "${SCRIPT_DIR}/keystore.properties" ]]; then
        echo "     Release signing: using ${SCRIPT_DIR}/keystore.properties"
    elif [[ -n "${AIVPN_UPLOAD_STORE_FILE:-}" && -n "${AIVPN_UPLOAD_STORE_PASSWORD:-}" && -n "${AIVPN_UPLOAD_KEY_ALIAS:-}" && -n "${AIVPN_UPLOAD_KEY_PASSWORD:-}" ]]; then
        echo "     Release signing: custom keystore (${AIVPN_UPLOAD_KEY_ALIAS})"
    else
        echo "     Release signing: no custom keystore configured, Gradle will emit unsigned APK"
    fi
fi

if [[ ! -x "${SCRIPT_DIR}/gradlew" ]]; then
    chmod +x "${SCRIPT_DIR}/gradlew" || true
fi

GRADLE_ARGS=(--no-daemon -Dkotlin.compiler.execution.strategy=in-process)

(
    cd "${SCRIPT_DIR}"
    ./gradlew --stop >/dev/null 2>&1 || true
)

if [[ "${BUILD_TYPE}" == "release" ]]; then
    (
        cd "${SCRIPT_DIR}"
        ./gradlew "${GRADLE_ARGS[@]}" app:assembleRelease
    )

    RELEASE_APK_SIGNED="${SCRIPT_DIR}/app/build/outputs/apk/release/app-universal-release.apk"
    RELEASE_APK_UNSIGNED="${SCRIPT_DIR}/app/build/outputs/apk/release/app-universal-release-unsigned.apk"
    RELEASE_APK_SIGNED_LOCAL="${SCRIPT_DIR}/app/build/outputs/apk/release/app-universal-release-signed.apk"

    if [[ -f "${RELEASE_APK_SIGNED}" ]]; then
        cp -f "${RELEASE_APK_SIGNED}" "${APK_DST}"
        echo "  Copied signed release APK -> ${APK_DST}"
    elif [[ -f "${RELEASE_APK_UNSIGNED}" ]]; then
        echo "  release APK is unsigned. Attempting to sign with debug keystore..."
        if command -v jarsigner >/dev/null 2>&1 && [[ -f "${HOME}/.android/debug.keystore" ]]; then
            rm -f "${RELEASE_APK_SIGNED_LOCAL}"
            jarsigner \
                -keystore "${HOME}/.android/debug.keystore" \
                -storepass android \
                -keypass android \
                -signedjar "${RELEASE_APK_SIGNED_LOCAL}" \
                "${RELEASE_APK_UNSIGNED}" \
                androiddebugkey >/dev/null

            if jarsigner -verify -certs "${RELEASE_APK_SIGNED_LOCAL}" >/dev/null 2>&1; then
                cp -f "${RELEASE_APK_SIGNED_LOCAL}" "${APK_DST}"
                echo "  Signed release APK with debug.keystore -> ${APK_DST}"
            else
                echo "  WARNING: release signing verification failed. Falling back to debug APK..."
            fi
        else
            echo "  WARNING: jarsigner/debug.keystore unavailable. Falling back to debug APK..."
        fi

        if [[ ! -f "${APK_DST}" || "$(shasum -a 256 "${APK_DST}" | awk '{print $1}')" == "$(shasum -a 256 "${RELEASE_APK_UNSIGNED}" | awk '{print $1}')" ]]; then
            echo "  Building signed debug APK as installable fallback..."
            (
                cd "${SCRIPT_DIR}"
                ./gradlew "${GRADLE_ARGS[@]}" app:assembleDebug
            )
            DEBUG_APK="${SCRIPT_DIR}/app/build/outputs/apk/debug/app-universal-debug.apk"
            if [[ -f "${DEBUG_APK}" ]]; then
                cp -f "${DEBUG_APK}" "${APK_DST}"
                echo "  Copied debug APK fallback -> ${APK_DST}"
            else
                echo "ERROR: debug fallback APK not found: ${DEBUG_APK}"
                exit 1
            fi
        fi
    else
        echo "ERROR: release APK not found in expected output paths."
        exit 1
    fi
else
    (
        cd "${SCRIPT_DIR}"
        AIVPN_ANDROID_ABIS="${SELECTED_ABIS}" \
        AIVPN_ANDROID_UNIVERSAL_DEBUG_APK=false \
        ./gradlew "${GRADLE_ARGS[@]}" app:assembleDebug
    )
    if [[ "${#ABI_LIST[@]}" -eq 1 ]]; then
        DEBUG_APK="${SCRIPT_DIR}/app/build/outputs/apk/debug/app-${ABI_LIST[0]}-debug.apk"
    else
        DEBUG_APK="${SCRIPT_DIR}/app/build/outputs/apk/debug/app-universal-debug.apk"
    fi
    if [[ -f "${DEBUG_APK}" ]]; then
        cp -f "${DEBUG_APK}" "${APK_DST}"
        echo "  Copied debug APK -> ${APK_DST}"
    else
        echo "ERROR: debug APK not found: ${DEBUG_APK}"
        exit 1
    fi
fi

echo "==> Final artifact: ${APK_DST}"
ls -lh "${APK_DST}"
