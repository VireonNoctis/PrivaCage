pluginManagement {
    repositories { google(); mavenCentral(); gradlePluginPortal() }
}
dependencyResolutionManagement {
    repositories { google(); mavenCentral() }
}
rootProject.name = "privacage-android"
include(":app", ":android-core")
project(":android-core").projectDir = file("../android-core")
