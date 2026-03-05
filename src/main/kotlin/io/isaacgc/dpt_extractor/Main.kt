package io.isaacgc.dpt_extractor

import java.io.File

fun main(args: Array<String>) {

    if (args.isEmpty() || args.contains("-h") || args.contains("--help")) {
        printHelp()
        return
    }

    var apkPath: String? = null
    var outputDir: String? = "out"
    var verbose: Boolean = false

    var i = 0
    while (i < args.size) {
        when (val arg = args[i]) {
            "-o", "--output" ->  outputDir = args.getOrNull(++i) ?: exitError("Missing value for $arg")
            "-v", "--verbose" -> verbose = true
            else -> {
                if (arg.startsWith("-")) exitError("Unknown option: $arg")
                if (apkPath == null) { apkPath = arg } else exitError("Unexpected argument: $arg")
            }
        }

        i++
    }

    if (apkPath == null) exitError("No APK file specified")
    val apkFile = File(apkPath!!)
    if (!apkFile.isFile) {
        exitError("APK file not found: $apkPath")
    }


    try {
        ApkExtractor().extractApk(apkFile, File(outputDir))
    } catch (e: Exception) {
        System.err.println("\n[-] Error: ${e.message}")
        if (verbose) e.printStackTrace()
        System.exit(1)
    }

}


private fun exitError(msg: String): Nothing {
    System.err.println("[!] $msg  (run --help for usage)")
    System.exit(1)
    throw RuntimeException("unreachable")
}

private fun printHelp() = println("""
dpt-shell extractor
(Created by Isaac Gray-Christensen)

Original dpt-shell source can be found here: https://github.com/luoyesiqiu/dpt-shell

This tool restores method bytecodes from APKS protected/packed by dpt-shell. It will output them as dex files in
the chosen directory

USAGE:
    java -jar dpt-extractor.jar <apk> [OPTIONS]
    
OPTIONS:
  -o, --output <dir> Output directory for restored/rebuilt dex files (default is 'out')
  -v, --verbose      Verbose help
  -h, --help         
""".trimIndent())