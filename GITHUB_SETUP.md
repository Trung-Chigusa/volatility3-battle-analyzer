# GitHub setup

Day la quy trinh day tool len GitHub ma khong day nham memory dump, cache, API key, hay file build nang.

## 1. Kiem tra truoc khi push

```powershell
git status --short
git ls-files
```

Khong duoc thay cac file nhu:

- `*.raw`
- `*.dmp`
- `ctf_mem/`
- `ctf_out/`
- `battle_out/`
- `.vol3_cache/`
- `dist/`
- `build/`
- `.env`

## 2. Tao repository tren GitHub

Vao GitHub va tao repo moi, vi du:

```text
volatility3-battle-analyzer
```

Nen chon `Private` neu tool co logic rieng cho thuc chien, CTF, hoac forensic case noi bo.
Khong tick tao README/gitignore/license tren GitHub neu repo local da co san.

## 3. Gan remote va push

Thay `Trung-Chigusa` va ten repo neu ban dat ten khac:

```powershell
git remote add origin https://github.com/Trung-Chigusa/volatility3-battle-analyzer.git
git branch -M main
git push -u origin main
```

## 4. Dua EXE len GitHub Release

Khong nen commit `dist/Volatility3Analyzer.exe` vao repo. Hay upload EXE vao tab `Releases` cua GitHub.

Build EXE lai bang:

```powershell
pyinstaller --noconfirm build_spec\volatility_gui.spec
```

File build xong nam o:

```text
dist\Volatility3Analyzer.exe
```

## 5. Lenh lam viec hang ngay

```powershell
git status
git add .
git commit -m "Update analyzer"
git push
```
