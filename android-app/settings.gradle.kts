pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.application") version "8.10.1"
        id("org.jetbrains.kotlin.android") version "2.2.20"
        id("org.jetbrains.kotlin.jvm") version "2.2.20"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "privacage-android"
include(":app", ":android-core")
project(":android-core").projectDir = file("../android-core")
