import java.util.Properties
import java.io.FileInputStream
import java.io.ByteArrayOutputStream
import java.io.File

plugins {
    id("com.android.application")
    id("kotlin-android")
    // The Flutter Gradle Plugin must be applied after the Android and Kotlin Gradle plugins.
    id("dev.flutter.flutter-gradle-plugin")
}

val gitBuildNumber = run {
    val stdout = ByteArrayOutputStream()
    rootProject.exec {
        commandLine("git", "rev-list", "--count", "HEAD")
        standardOutput = stdout
    }
    // Play Store already has v124; ensure version code exceeds it.
    // Base offset 120 + git count (6) = 126 > 124.
    stdout.toString().trim().toInt() + 120
}

val keystoreProperties = Properties()
val keystorePropertiesFile = rootProject.file("key.properties")
if (keystorePropertiesFile.exists()) {
    keystoreProperties.load(FileInputStream(keystorePropertiesFile))
}

val workspaceRootDir = rootProject.projectDir.parentFile.parentFile
val rustBuildScript = File(workspaceRootDir, "scripts/build-android-native.sh")
val rustArm64Output = file("src/main/jniLibs/arm64-v8a/libbonded_ffi.so")
val rustArmV7Output = file("src/main/jniLibs/armeabi-v7a/libbonded_ffi.so")
val rustX64Output = file("src/main/jniLibs/x86_64/libbonded_ffi.so")

val buildRustAndroidNative by tasks.registering(Exec::class) {
    group = "build"
    description = "Builds Android Rust JNI libraries for bonded-ffi"
    workingDir = workspaceRootDir
    commandLine("bash", rustBuildScript.absolutePath)
    inputs.file(rustBuildScript)
    outputs.files(rustArm64Output, rustArmV7Output, rustX64Output)
    // Cargo tracks Rust incremental state; always run this task for release builds to avoid stale JNI artifacts.
    outputs.upToDateWhen { false }

    doFirst {
        check(rustBuildScript.exists()) {
            "Rust Android build script not found at ${rustBuildScript.absolutePath}"
        }
    }
}

tasks.matching { it.name == "preBuild" || it.name == "bundleRelease" || it.name == "assembleRelease" || it.name == "bundleDebug" || it.name == "assembleDebug" }.configureEach {
    dependsOn(buildRustAndroidNative)
}

tasks.matching { it.name.contains("Release") && it.name.endsWith("JniLibFolders") }.configureEach {
    dependsOn(buildRustAndroidNative)
}

android {
    namespace = "com.bonded.bonded_app"
    compileSdk = flutter.compileSdkVersion
    ndkVersion = flutter.ndkVersion

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_11
        targetCompatibility = JavaVersion.VERSION_11
    }

    defaultConfig {
        // TODO: Specify your own unique Application ID (https://developer.android.com/studio/build/application-id.html).
        applicationId = "com.bonded.bonded_app"
        // You can update the following values to match your application needs.
        // For more information, see: https://flutter.dev/to/review-gradle-config.
        minSdk = flutter.minSdkVersion
        targetSdk = flutter.targetSdkVersion
        versionCode = gitBuildNumber // flutter.versionCode
        versionName = flutter.versionName
    }

    signingConfigs {
        create("release") {
            keyAlias = (keystoreProperties["keyAlias"] ?: "") as String
            keyPassword = (keystoreProperties["keyPassword"] ?: "") as String
            storeFile = keystoreProperties["storeFile"]?.let { file(it) }
            storePassword = (keystoreProperties["storePassword"] ?: "") as String
        }
    }

    buildTypes {
        release {
            signingConfig = signingConfigs.getByName("release")
        }
    }
}

kotlin {
    compilerOptions {
        jvmTarget.set(org.jetbrains.kotlin.gradle.dsl.JvmTarget.JVM_11)
    }
}

flutter {
    source = "../.."
}

dependencies {
    // Consider viability of com.google.android.gms:play-services-cronet
    implementation("org.chromium.net:cronet-embedded:143.7445.0")
    // Play in-app updates: the dashboard checks whether a newer build is
    // available on the Play track and offers the update flow.
    implementation("com.google.android.play:app-update:2.1.0")
    testImplementation("junit:junit:4.13.2")
}
