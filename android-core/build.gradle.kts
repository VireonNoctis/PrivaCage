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
    useJUnitPlatform {
        excludeTags("performance")
    }
}

tasks.register<Test>("performanceTest") {
    description = "Runs relative DNS performance measurements; no timing thresholds are enforced."
    group = "verification"
    val testSourceSet = sourceSets["test"]
    testClassesDirs = testSourceSet.output.classesDirs
    classpath = testSourceSet.runtimeClasspath
    useJUnitPlatform {
        includeTags("performance")
    }
    systemProperty(
        "performance.output",
        layout.buildDirectory.file("reports/performance/dns-benchmark.json").get().asFile.absolutePath
    )
    testLogging {
        events("passed", "failed", "skipped")
        showStandardStreams = true
    }
}

dependencies {
    implementation("org.bouncycastle:bcprov-jdk18on:1.86")
    testImplementation(kotlin("test-junit5"))
    testImplementation("org.junit.jupiter:junit-jupiter:5.12.2")
}
