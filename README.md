# DPT-Extractor

Used to extract dex code from dpt-shell: https://github.com/luoyesiqiu/dpt-shell

## Current status

- [X] extracting dex  
- [ ] zipalign and repack (work-in-progress)  
- [ ] resign APK


### Building it

#### Requirements:

- Java JDK 21+

1. `git clone https://github.com/Isaac-GC/dpt-extractor`
2. `cd dpt-extractor`
3. `./gradlew jar`
4. The built jar file will be under `build/libs/dpt-extractor.jar`

### Usage

`java -jar dpt-extractor.jar <apk> [OPTIONS]`

- Example: `java -jar dpt-extractor.jar my.apk`
- Example w/custom out directory: `java -jar dpt-extractor.jar my.apk --out ./decrypted_sources`