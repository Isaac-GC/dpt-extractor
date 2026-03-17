plugins {
    kotlin("jvm") version "2.3.0"
    application
}

group = "io.isaacgc"
version = "0.1-Beta"

application {
    mainClass = "io.isaacgc.dpt_extractor.MainKt"
}

repositories {
    mavenCentral()
}

dependencies {
    implementation(kotlin("stdlib"))
//    implementation("com.google.code.gson:gson:2.13.2")
    testImplementation(kotlin("test"))
}

//kotlin {
//    jvmToolchain(21)
//}

tasks.test {
    useJUnitPlatform()
}

tasks.jar {
    manifest {
        attributes["Main-Class"] = application.mainClass
    }

    from(configurations.runtimeClasspath.get().map { if (it.isDirectory) it else zipTree(it) })
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    archiveFileName.set("dpt-extractor.jar")
}