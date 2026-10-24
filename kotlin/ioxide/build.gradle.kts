plugins {
    kotlin("jvm")
}

kotlin {
    jvmToolchain(25)
}

dependencies {
    testImplementation(kotlin("test"))
}

tasks.test {
    useJUnitPlatform()
    jvmArgs("--enable-native-access=ALL-UNNAMED")
    // The BoringSSL the C# package ships, from this checkout.
    systemProperty("ioxide.boringssl", rootProject.file("../src/ioxide/runtimes/linux-x64/native/libioxide_boringssl.so").absolutePath)
}
