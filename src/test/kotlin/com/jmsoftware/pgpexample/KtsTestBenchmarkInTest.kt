package com.jmsoftware.pgpexample

import com.jmsoftware.pgpexample.util.logger
import org.openjdk.jmh.annotations.*
import java.util.concurrent.*
import kotlin.math.cos
import kotlin.math.sqrt

/**
 * # KtsTestBenchmarkInTest
 *
 * Change description here.
 *
 * @author Johnny Miller (锺俊), email: johnnysviva@outlook.com, 5/13/23 11:16 PM
 **/
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 0)
@Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
class KtsTestBenchmarkInTest {
    companion object {
        internal val log = logger()
    }
    private var data = 0.0

    @Setup
    fun setUp() {
        data = 3.0
        log.info("Done setup for ${this.javaClass.simpleName}")
    }

    @Benchmark
    fun sqrtBenchmark(): Double {
        return sqrt(data)
    }

    @Benchmark
    fun cosBenchmark(): Double {
        return cos(data)
    }
}
