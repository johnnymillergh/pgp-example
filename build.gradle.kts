import org.gradle.api.tasks.testing.logging.TestExceptionFormat.FULL
import org.gradle.api.tasks.testing.logging.TestLogEvent.*
import org.jetbrains.kotlin.gradle.tasks.KotlinCompile

plugins {
    id("org.springframework.boot") version "3.0.5"
    id("io.spring.dependency-management") version "1.1.0"
    kotlin("jvm") version "1.7.22"
    kotlin("plugin.spring") version "1.7.22"
}

group = "com.jmsoftware"
version = "0.0.1-SNAPSHOT"
java.sourceCompatibility = JavaVersion.VERSION_17

repositories {
    mavenCentral()
}

dependencies {
    implementation("org.springframework.boot:spring-boot-starter")
    implementation("org.jetbrains.kotlin:kotlin-reflect")
    testImplementation("org.springframework.boot:spring-boot-starter-test")

    // https://mvnrepository.com/artifact/org.bouncycastle/bcpg-jdk18on
    implementation("org.bouncycastle:bcpg-jdk18on:1.72.2")
    // https://mvnrepository.com/artifact/com.google.guava/guava
    implementation("com.google.guava:guava:31.1-jre")
    // https://mvnrepository.com/artifact/org.apache.commons/commons-lang3
    implementation("org.apache.commons:commons-lang3:3.12.0")
    // https://mvnrepository.com/artifact/commons-io/commons-io
    implementation("commons-io:commons-io:2.11.0")
}

tasks.withType<KotlinCompile> {
    kotlinOptions {
        freeCompilerArgs = listOf("-Xjsr305=strict")
        jvmTarget = "17"
    }
}

tasks.withType<Test> {
    useJUnitPlatform()
}

// https://docs.gradle.org/current/userguide/performance.html#parallel_test_execution
tasks.withType<Test>().configureEach {
    // The normal approach is to use some number less than or equal to the number of CPU cores you have,
    // such as this algorithm:
    maxParallelForks = (Runtime.getRuntime().availableProcessors() / 2).takeIf { it > 0 } ?: 1
    // To fork a new test VM after a certain number of tests have run
    setForkEvery(100)
}

// https://docs.gradle.org/current/dsl/org.gradle.api.tasks.testing.Test.html
tasks.withType<Test> {
    // Configuration parameters to execute top-level classes in parallel but methods in the same thread
    // https://www.jvt.me/posts/2021/03/11/gradle-speed-parallel/
    systemProperties["junit.jupiter.execution.parallel.enabled"] = "true"
    systemProperties["junit.jupiter.execution.parallel.mode.default"] = "concurrent"
    systemProperties["junit.jupiter.execution.parallel.mode.classes.default"] = "concurrent"
    // Discover and execute JUnit Platform-based tests
    useJUnitPlatform()
    failFast = true
    // https://technology.lastminute.com/junit5-kotlin-and-gradle-dsl/
    testLogging {
        // set options for log level LIFECYCLE
        events = mutableSetOf(
            FAILED,
            PASSED,
            SKIPPED,
            STANDARD_OUT
        )
        exceptionFormat = FULL
        showStandardStreams = true
        showExceptions = true
        showCauses = true
        showStackTraces = true
        // set options for log level DEBUG and INFO
        debug {
            events = mutableSetOf(
                FAILED,
                PASSED,
                SKIPPED,
                STANDARD_OUT
            )
            exceptionFormat = FULL
        }
        info {
            events = debug.events
            exceptionFormat = debug.exceptionFormat
        }
    }
}
