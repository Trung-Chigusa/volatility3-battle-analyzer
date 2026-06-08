# Volatility Battle CLI

Portable command layer for this local Volatility3 bundle.

## Start

From the rebuilt executable:

```powershell
.\dist\Volatility3Analyzer.exe --cli -f "C:\Users\Ninym\Desktop\volatility3-2.26.2\DESKTOP-1LI6VC6-20260522-105906.raw"
```

Run one command directly:

```powershell
.\dist\Volatility3Analyzer.exe --cli -f "C:\path\mem.raw" info
.\dist\Volatility3Analyzer.exe --cli -f "C:\path\mem.raw" ps --limit 40
.\dist\Volatility3Analyzer.exe --cli -f "C:\path\mem.raw" tree --source filescan --out trees\filescan.txt
.\dist\Volatility3Analyzer.exe --cli -f "C:\path\mem.raw" dump-images --mode both --out images
```

Script launcher for development:

```powershell
.\battle-cli.bat -f "C:\Users\Ninym\Desktop\volatility3-2.26.2\DESKTOP-1LI6VC6-20260522-105906.raw"
```

Or run one command directly:

```powershell
.\battle-cli.bat -f "C:\path\mem.raw" info
.\battle-cli.bat -f "C:\path\mem.raw" ps --limit 40
.\battle-cli.bat -f "C:\path\mem.raw" tree --source filescan --out trees\filescan.txt
.\battle-cli.bat -f "C:\path\mem.raw" dump-images --mode both --out images
```

Inside the interactive shell, press `Tab` to complete commands and plugin names.

## Useful Commands

```text
status                         Show selected dump/cache/output/symbol paths
plugins [query]                List Volatility plugins
run <plugin> [key=value]       Run any plugin through the reusable runner
vol <raw vol.py args>          Run original Volatility CLI with portable cache

info                           windows.info.Info
ps                             windows.pslist.PsList
pstree                         windows.pstree.PsTree
psscan                         windows.psscan.PsScan
cmdline                        windows.cmdline.CmdLine
net                            windows.netstat.NetStat
files                          windows.filescan.FileScan

triage --out triage_case01     Save common triage output as JSON
tree --source filescan         Show file/path artifacts as a tree
tree --source mft              Build a tree from MFT records
dump-images --mode both        Dump cached image files and carve raw image bytes
carve-images --max-size 64M    Only carve image signatures from raw memory
dump-proc <pid>                Dump EXE/DLL images for one process
```

## Image Extraction Notes

`dump-images --mode cache` uses `windows.dumpfiles.DumpFiles` with an image-extension filter. This recovers file objects that Windows had cached in memory.

`dump-images --mode carve` scans the raw memory image for JPEG, PNG, GIF, BMP, WebP, and ICO signatures. This can find images that are not exposed as file objects, but it may miss fragmented images.

Each image run writes:

```text
manifest.json
manifest.csv
cache\
carved\
```

The manifest records output path, format, offset when carved, size, SHA256, and validation notes.

In the GUI, the Image Dump view shows the exact output folder and opens it when the job finishes. By default, EXE output is written next to the executable:

```text
dist\battle_out\<output_name>\
```

Use the VirusTotal view to hash-check dumped files. It performs hash lookups only by default and does not upload unknown files.

## Portable Volatility

For original Volatility CLI usage with local cache/symbol/output paths:

```powershell
.\vol-portable.bat -f "C:\path\mem.raw" windows.info.Info
.\vol-portable.bat -f "C:\path\mem.raw" -r pretty windows.pslist.PsList
```
