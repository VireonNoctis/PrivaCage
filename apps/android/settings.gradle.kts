pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
    plugins {
        id("com.android.application") version "8.10.1"
        id("com.android.test") version "8.10.1"
        id("org.jetbrains.kotlin.android") version "2.2.20"
    }
}

dependencyResolutionManagement {
    repositories {
        google()
        mavenCentral()
    }
}

rootProject.name = "privacage-android"
include(":performance-macrobenchmark")
project(":performance-macrobenchmark").projectDir = file("test")
