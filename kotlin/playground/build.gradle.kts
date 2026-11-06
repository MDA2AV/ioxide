plugins {
    kotlin("jvm")
    application
}

kotlin {
    jvmToolchain(25)
}

dependencies {
    implementation(project(":ioxide"))
}

// The BoringSSL the C# package ships, found in this checkout; a host elsewhere sets -Dioxide.boringssl itself.
val boringSsl = rootProject.file("../src/ioxide/runtimes/linux-x64/native/libioxide_boringssl.so").absolutePath

application {
    mainClass = "playground.MainKt"
    applicationDefaultJvmArgs = listOf("--enable-native-access=ALL-UNNAMED", "-Dioxide.boringssl=$boringSsl")
}
