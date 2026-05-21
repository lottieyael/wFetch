# wFetch

Intelligens rendszerelemző és hálózati diagnosztikai eszköz Windows rendszerre

![Windows 10/11](https://img.shields.io/badge/Windows-10%2F11-blue) ![Tauri 2](https://img.shields.io/badge/Tauri-2-brightgreen) ![Rust](https://img.shields.io/badge/Backend-Rust-orange)

---

## A projektről

A wFetch egy könnyűsúlyú asztali alkalmazás, amely gyors hardver-áttekintést, AI-alapú elemzést,
hálózati felderítést és háttérfigyelést nyújt – mindezt egyetlen, modern felületen. Célcsoportja
az IT rendszergazdáktól a helpdesk munkatársakig és az egyéni felhasználókig terjed.

---

## Főbb funkciók

- **Azonnali hardverleolvasás** – CPU, RAM, háttértár, GPU, hálózati adapterek ~30 ms alatt,
  külső program telepítése nélkül
- **AI-alapú elemzés** – DeepSeek nyelvi modell természetes, a felhasználó által választott
  nyelven magyarázza az adatokat
- **LAN-felderítés + Excel export** – egy kattintásra feltérképezi a helyi hálózatot és
  exportálja az eredményeket
- **Háttérfigyelés** – CPU/RAM monitorozás <5 MB memóriahasználattal, automatikus
  incidens-pillanatképekkel
- **Többnyelvű felület** – angol, magyar, német, spanyol, francia, japán
- **5 téma** – liquid glass dizájn, teljes mértékben testreszabható
- **Pehelykönnyű** –  kb. 12 MB telepített méret a Tauri keretrendszernek köszönhetően

---

## Technológiai stackem

| Réteg          | Technológia       | Licensz          |
|----------------|-------------------|------------------|
| Keretrendszer  | Tauri 2           | MIT              |
| Frontend       | React 18          | MIT              |
| Backend        | Rust              | MIT / Apache 2.0 |
| Excel export   | rust_xlsxwriter   | MIT              |
| HTTP kliens    | reqwest           | MIT / Apache 2.0 |
| Windows API    | windows crate     | MIT              |
| AI elemzés     | DeepSeek API      | –                |
| Fizetés        | LemonSqueezy      | –                |

---

## Telepítés

A telepítő letölthető .msi és .exe formátumban, Windows 10 és Windows 11 rendszerre egyaránt.

> **Megjegyzés:** Windows SmartScreen figyelmeztetést jeleníthet meg aláíratlan telepítőnél.
> Ez ismert, folyamatban lévő ügy (code signing tanúsítvány kell).

---

## Rendszerkövetelmények

- Windows 10 (1903+) vagy Windows 11
- x64 architektúra
- ~12 MB szabad lemezterület
- Hálózati kapcsolat (AI elemzéshez és LAN felderítéshez)

---

## Előfizetési csomagok

| Funkció                        | Free        | Pro (2 000 Ft/hó) |
|--------------------------------|-------------|-------------------|
| Helyi rendszerfelmérés         | ✅          | ✅                |
| Többnyelvű felület             | ✅          | ✅                |
| AI-alapú elemzés               | ❌          | ✅                |
| Prémium témák                  | ❌          | ✅                |
| Háttérfigyelés                 | Korlátozott | ✅                |
| LAN diagnosztika + Excel export| ❌          | ✅                |
| Céges telepítés (MSI/GPO)      | ❌          | ✅                |

Éves előfizetés: **20 000 Ft/év**. Licenckezelés LemonSqueezy platformon keresztül,
az alkalmazáson belül.

---

## Licensz és szellemi tulajdon

A wFetch teljes egészében saját tervezésű és fejlesztésű szoftver.
Minden felhasznált nyílt forráskódú komponens megengedő licensszel rendelkezik
(MIT / Apache 2.0), kereskedelmi felhasználást nem korlátoznak.
