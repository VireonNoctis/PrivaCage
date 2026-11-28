plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
    id("de.mannodermaus.android-junit") version "2.0.2"
}

val dnsPerformanceOnly = providers.gradleProperty("dnsPerformanceOnly").isPresent

android {
    namespace = "org.privacage.android"
    compileSdk = 36

    sourceSets {
        getByName("main") {
            manifest.srcFile("main/AndroidManifest.xml")
            java.setSrcDirs(listOf("main"))
            res.setSrcDirs(listOf("main/res"))
            jniLibs.setSrcDirs(listOf("main/jniLibs"))
            assets.srcDir("../../shared/tracker-db")
            assets.srcDir("../../shared/app-alternatives")
            assets.srcDir("../../docs/privacy")
        }
        getByName("test") {
            java.setSrcDirs(
                if (dnsPerformanceOnly) {
                    listOf("test/dns")
                } else {
                    listOf(
                        "test/API",
                        "test/audit",
                        "test/crypto",
                        "test/dns",
                        "test/interface",
                        "test/legal",
                        "test/metadata",
                        "test/security",
                        "test/sync"
                    )
                }
            )
        }
    }

    testOptions {
        unitTests.all {
            it.systemProperty("privacage.repo-root", rootProject.projectDir.parentFile.parentFile.absolutePath)
        }
    }

    defaultConfig {
        applicationId = "org.privacage.android"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "0.2.0-experimental"
    }

    buildTypes {
        create("benchmark") {
            initWith(getByName("release"))
            isDebuggable = false
            signingConfig = signingConfigs.getByName("debug")
            matchingFallbacks += listOf("release")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
}

kotlin {
    jvmToolchain(17)
}

junitPlatform {
    filters {
        if (dnsPerformanceOnly) {
            includeTags("performance")
        } else {
            excludeTags("performance")
        }
    }
}

val performanceOutput = layout.buildDirectory.file("reports/performance/dns-benchmark.json").get().asFile.absolutePath

tasks.withType<org.gradle.api.tasks.testing.Test>().configureEach {
    classpath += files("../../shared/crypto/test-vectors")
    systemProperty("performance.output", performanceOutput)
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    implementation("com.android.tools.build:apksig:8.10.1")
    implementation("androidx.profileinstaller:profileinstaller:1.4.1")

    testImplementation(platform("org.junit:junit-bom:5.14.1"))
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter-api")
    testImplementation("org.junit.jupiter:junit-jupiter-params")
    testRuntimeOnly("org.junit.jupiter:junit-jupiter-engine")
    testImplementation("junit:junit:4.13.2")
    testRuntimeOnly("org.junit.vintage:junit-vintage-engine")
    testImplementation("org.json:json:20260719")
}
