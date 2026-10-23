plugins {
    id("org.jetbrains.kotlin.jvm")
}

sourceSets {
    test {
        resources.srcDir("../shared/crypto/test-vectors")
    }
}

repositories {
    mavenCentral()
}

kotlin {
    jvmToolchain(17)
}

tasks.test {
    useJUnitPlatform()
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
}
