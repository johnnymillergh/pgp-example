package com.jmsoftware.pgpexample

import org.openjdk.jmh.annotations.*
import java.util.concurrent.*
import kotlin.math.cos
import kotlin.math.sqrt

/**
 * # KtsTestBenchmarkInMain
 *
 * Change description here.
 *
 * @author Johnny Miller (锺俊), email: johnnysviva@outlook.com, 5/13/23 11:16 PM
 **/
@State(Scope.Benchmark)
@Fork(1)
@Warmup(iterations = 0)
@Measurement(iterations = 1, time = 1, timeUnit = TimeUnit.SECONDS)
class KtsTestBenchmarkInMain {
    private var data = 0.0

    @Setup
    fun setUp() {
        data = 3.0
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
