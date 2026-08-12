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
    var rebuild: Boolean = false
    var rebuiltApk: String? = null
    var keystore: String? = null
    var storePass: String = "android"
    var keyAlias: String? = null
    var writeV4: Boolean = false

    var i = 0
    while (i < args.size) {
        when (val arg = args[i]) {
            "-o", "--output" ->  outputDir = args.getOrNull(++i) ?: exitError("Missing value for $arg")
            "-v", "--verbose" -> verbose = true
            "-r", "--rebuild" -> rebuild = true
            "--rebuilt-apk" -> {
                rebuiltApk = args.getOrNull(++i) ?: exitError("Missing value for $arg")
                rebuild = true
            }
            "--keystore" -> {
                keystore = args.getOrNull(++i) ?: exitError("Missing value for $arg")
                rebuild = true
            }
            "--v4" -> {
                writeV4 = true
                rebuild = true
            }
            "--storepass" -> storePass = args.getOrNull(++i) ?: exitError("Missing value for $arg")
            "--alias" -> keyAlias = args.getOrNull(++i) ?: exitError("Missing value for $arg")
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
        val outDir = File(outputDir)
        ApkExtractor().extractApk(apkFile, outDir)

        // Put the restored dex files back into a working (signed) apk if asked for
        if (rebuild) {
            val target = File(rebuiltApk ?: "${apkFile.nameWithoutExtension}_restored.apk")
            ZipAlign().rebuild(apkFile, outDir, target,
                keystore = keystore?.let { File(it) },
                storePass = storePass,
                keyAlias = keyAlias,
                writeV4 = writeV4)
        }
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
  -o, --output <dir>    Output directory for restored/rebuilt dex files (default is 'out')
  -r, --rebuild         Repack the restored dex files into a signed apk (aligned, v1 + v2)
      --rebuilt-apk <f> Where to write the rebuilt apk (implies --rebuild)
      --keystore <f>    Keystore to sign with, a throwaway one is made if left out (implies --rebuild)
      --storepass <p>   Keystore password (default is 'android')
      --alias <a>       Key alias to use (defaults to the first one in the keystore)
      --v4              Also write a v4 .idsig sidecar (incomplete, see V4Signer)
  -v, --verbose         Verbose help
  -h, --help
""".trimIndent())