# BwE Py Zlib Extractor

BwE Py Zlib Extractor is a Python utility for scanning binary files (e.g., `.exe`, `.dmp`, `.tmp`, `.dump`, `.bin`) for zlib-compressed streams, decompressing them, and optionally scanning for specific “special headers” that mark embedded Python bytecode (`.pyc`). If such headers are found, it attempts to decompile the embedded `.pyc` files using the `pydumpck` utility (and possibly `pycdc` under the hood).

## Features

1. **Automatic Zlib Detection**  
   Searches for common zlib signatures (`0x78 0x9C` and `0x78 0xDA`) in a given file and attempts to decompress them.

2. **Threaded Decompression**  
   Uses multithreading for faster processing of larger files with many compressed streams.

3. **Special Header Detection**  
   Checks decompressed streams for a custom 16-byte header (`E3 00 00 00 00 00 00 00 00 00 00 00 00 05 00 00`) to identify potential Python bytecode.

4. **PYC Rebuild and Decompile**  
   If the special header is found, the tool rebuilds a `.pyc` file by prepending a header based on the target Python version and runs `pydumpck` to attempt decompilation.

## Usage

1. Place any `.exe`, `.dmp`, `.tmp`, `.dump`, or `.bin` file in the same directory as the script.
2. Run the script from the command line:
   ```bash
   python BwE_Py_Zlib_Extractor.py
   ```
3. When prompted, select the file to decompress from the list.
4. The script will:
   - Parse the file for zlib signatures.
   - Decompress each found stream.
   - Check for special headers in any decompressed data.
   - If found, rebuild and attempt to decompile the `.pyc`.
5. Output files (decompressed `.bin` files, possible `.pyc` files, and any successfully decompiled `.py`) appear in a folder named `<FILENAME>_Decompressed`.

## Use Case Example

Here we have an application we're trying to extract but its giving us a strange error regarding PYZ
![Example](https://i.imgur.com/HntcZWs.png)
It seemingly only extracted 14 .PYC files
![Not Enough](https://i.imgur.com/o3WJhDF.png)
However when using the ZLib Extractor...
![177](https://i.imgur.com/ZoneftZ.png)
As you can see the result is much better!


## Notes and Caveats

- **Multithreading**: The tool uses multiple threads for decompression. This may speed things up for large input files.
- **Safe Printing**: We use a thread lock (`safe_print()`) to prevent interleaved console output from multiple threads.
- **Decompilation Success**: Some `.pyc` files may be incomplete or corrupted, resulting in decompilation failures.
- **Header Assumption**: The 16-byte signature is specific to certain embedded Python bytecode. Adjust as needed for your use case.
- **Legality**: Use responsibly and ensure you have permission to inspect or reverse-engineer any files.

## License

This project is not under a specific license. Feel free to adapt or modify as required. Just don't be a dick and copy and rename it as your own work :)
