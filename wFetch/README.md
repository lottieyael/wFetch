# wFetch

Windows‑fókuszú Tauri + React asztali alkalmazás, ami gyorsan összegzi a helyi gép hardver/szoftver adatait (OS/CPU/RAM/Disk/GPU/Network), opcionálisan AI‑val “érthető nyelvű” elemzést készít, valamint admin eszközként LAN hostokat felderít, távoli (WMI/DCOM) diagnosztikát futtat és Excel riportot exportál.

> Megjegyzés: a backend jelentős része Windows API‑kra és PowerShell‑re épít, ezért a projekt jelen állapotában gyakorlatilag Windows‑specifikus.

## Fő funkciók

- **Helyi rendszer összegzés**: OS/CPU/RAM/Disk azonnali megjelenítése; GPU és hálózati adapterek “lassú” betöltése.
- **AI elemzés** (DeepSeek chat endpoint): a rendszeradatokból emberi nyelvű tanácsok/összegzés.
- **Előfizetés/licenc** (LemonSqueezy): aktiválás, frissítés/validálás, deaktiválás; lokális cache fájlban.
- **Háttér monitor**: könnyű, periodikus CPU/memória figyelés; “incident” snapshot túlterhelés esetén, eseményként a frontend felé.
- **LAN diagnosztika + Excel export**: host felderítés, távoli CIM lekérdezések, `.xlsx` jelentés az Asztalra.

## Tech stack

- **Frontend**: React 18 + Vite
- **Desktop shell**: Tauri 2
- **Backend**: Rust (tokio, reqwest, windows crate)
- **Export**: rust_xlsxwriter

## Követelmények (Windows)

- Node.js 18+ (ajánlott 20+)
- pnpm
- Rust toolchain (MSVC)
- Tauri CLI (v2)

## Gyors indítás (fejlesztés)

```bash
pnpm install
pnpm tauri dev
```

Vite dev server: `http://localhost:1420`

## Build (release)

```bash
pnpm tauri build
```

## Konfiguráció / környezeti változók

### AI (DeepSeek)

Az AI elemzéshez a backend a `https://api.deepseek.com/chat/completions` endpointot hívja.

- `DEEPSEEK_API_KEY` (kötelező az AI funkcióhoz)

Fejlesztésnél a backend induláskor próbál `.env` fájlt betölteni (lásd `dotenvy`).

### LemonSqueezy checkout link

- `VITE_LEMONSQUEEZY_CHECKOUT_URL` (frontend env; ha üres, a “Buy” gomb hibát jelez)

### Fejlesztői build jelzők

A frontend a következőket használja:

- `import.meta.env.DEV`
- `import.meta.env.TAURI_ENV_DEBUG === "true"`

## Architektúra áttekintés

### Frontend ↔ Backend kommunikáció

A React UI `@tauri-apps/api/core` `invoke()` hívásokkal éri el a Rust parancsokat.

Főbb parancsok:

- `get_fast_system_info` → gyors OS/CPU/RAM/Disk + hostname/username
- `get_gpu_info` → GPU lista
- `get_network_info` → aktív adapterek
- `get_memory_info` → RAM frissítés (UI polling)
- `send_to_ai` → AI elemzés (rate limit UI oldalon)
- `scan_network_and_export_excel` → LAN host scan + távoli diagnosztika + Excel export
- `ls_*` → licenc/előfizetés kezelés
- `set_monitor_state`, `set_monitor_sensitivity`, `get_monitor_incidents` → háttér monitor

### Modulszerkezet (Rust)

- `src-tauri/src/lib.rs`: Tauri parancsok, adatmodellek, app indítás.
- `src-tauri/src/fetch.rs`: Windows API alapú “helyi gép” lekérdezések.
- `src-tauri/src/ps.rs`: PowerShell futtatás timeouttal.
- `src-tauri/src/discovery.rs`: LAN host felderítés (NetNeighbor + opcionális ping sweep).
- `src-tauri/src/diagnostics.rs`: távoli WMI/CIM lekérdezés DCOM-on.
- `src-tauri/src/export_excel.rs`: Excel export.
- `src-tauri/src/lemonsqueezy.rs`: licenc cache + LemonSqueezy API hívások.
- `src-tauri/src/monitor.rs`: háttér monitor + incident eventek.

## Biztonsági és üzemeltetési megjegyzések

- **AI kulcs**: a `DEEPSEEK_API_KEY` a backend környezetéből kerül beolvasásra. Ne commitáld.
- **Távoli diagnosztika (WMI/DCOM)**: vállalati hálózatokon gyakran tiltott; tűzfal/permission problémák várhatók.
- **CSP**: a `src-tauri/tauri.conf.json` `csp: null` értéke lazább. Release előtt érdemes szigorítani.

## Funkció- és API referencia (részletes)

Az alábbiak a projektben ténylegesen implementált, névvel rendelkező függvények (és fontos metódusok) leírásai. A frontendben a legtöbb “működés” React hook callbackekben van; itt a stabil, újrahasznált/névvel rendelkező függvényeket és a fő UI‑logika kulcspontjait dokumentáljuk.

---

# Backend (Rust, Tauri parancsok)

## `src-tauri/src/main.rs`

### `fn main()`

- **Felelősség**: Windows release buildben elrejti a plusz konzolablakot (`windows_subsystem = "windows"`), majd elindítja a Tauri alkalmazást.
- **Működés**: delegál `wfetch_lib::run()` felé.
- **Mellékhatás**: Tauri runtime indítása.

---

## `src-tauri/src/lib.rs`

### Adatszerkezetek

- `SystemInfo`: összefoglaló adatmodell (OS, CPU, RAM, system, GPU-k, disk, network).
- `CpuInfo`, `MemoryInfo`, `SystemInfoData`, `GpuInfo`, `DiskInfo`: részmodellek.
- `NetworkScanOptions`: hálózati scan opciók (host limit, szomszédok, ping sweep, timeout, concurrency).
- `ScanFailure`: hibás host (ip + hibaüzenet).
- `NetworkScanExportResult`: export összegzés (kimeneti útvonal + statisztika + failure lista).

### `async fn scan_network_and_export_excel(app: AppHandle, options: Option<NetworkScanOptions>) -> Result<NetworkScanExportResult, String>`

- **Tauri parancs**: igen (`#[tauri::command]`).
- **Felelősség**: LAN hostok felderítése, távoli diagnosztika futtatása minden hoston, majd Excel riport exportálása az Asztalra.
- **Bemenet**:
	- `app`: Tauri `AppHandle`, path feloldáshoz (Desktop mappa).
	- `options`: opcionális konfiguráció; hiány esetén default értékek.
- **Fő lépések**:
	1. `discovery::discover_hosts(...)` blocking feladatban (45s timeout).
	2. IP lista összeállítása.
	3. Ha üres → hibával visszatér (“No LAN hosts discovered …”).
	4. `Semaphore`‑ral korlátozott párhuzamos diagnosztika: hostonként `tokio::spawn` + `spawn_blocking` → `diagnostics::diagnose_host(...)`.
	5. Eredmények összegyűjtése; hibák esetén “placeholder” `RemoteSystemInfo` rekord `error` mezővel.
	6. Siker/hiba statisztika és `failures` lista felépítése.
	7. Kimeneti fájl: Desktop + `wfetch_network_diagnostics_YYYYMMDD_HHMMSS.xlsx`.
	8. `export_excel::write_diagnostics_xlsx(...)` blocking feladatban.
- **Kimenet**: `NetworkScanExportResult` (útvonal + számlálók + hibák).
- **Hibák**: discovery/export join error, path feloldás, export hiba, üres host lista.
- **Mellékhatás**: fájlt ír a Desktopra.

### `fn get_fast_system_info() -> SystemInfo`

- **Tauri parancs**.
- **Felelősség**: gyorsan megadható mezők (OS/CPU/RAM/Disk/hostname/username) visszaadása azonnali UI renderhez.
- **Működés**: `fetch::*` hívások; GPU/Network üres placeholder.
- **Indok**: GPU/Network enumeráció lehet lassabb, ezért kétlépcsős betöltés.

### `fn get_memory_info() -> MemoryInfo`

- **Tauri parancs**.
- **Felelősség**: aktuális RAM állapot lekérése.
- **Működés**: `fetch::get_memory_info()`.
- **UI használat**: a frontend 5 másodpercenként frissíti.

### `fn get_gpu_info() -> Vec<GpuInfo>`

- **Tauri parancs**.
- **Felelősség**: GPU adapterek listázása.
- **Működés**: `fetch::get_gpu_info()`.

### `fn get_network_info() -> Vec<String>`

- **Tauri parancs**.
- **Felelősség**: aktív hálózati adapterek “FriendlyName” listája.
- **Működés**: `fetch::get_network_info()`.

### `fn get_system_info() -> SystemInfo`

- **Tauri parancs**.
- **Felelősség**: teljes rendszerinformáció egyben.
- **Működés**: `get_fast_system_info()` + GPU/Network kitöltés.
- **Megjegyzés**: a frontend inkább a kétlépcsős fast/slow mintát használja.

### `async fn send_to_ai(system_info: SystemInfo, lang: Option<String>) -> Result<String, String>`

- **Tauri parancs**.
- **Felelősség**: a rendszeradatokat elküldi a DeepSeek chat API‑nak, és visszaadja a modell szöveges válaszát.
- **Bemenet**:
	- `system_info`: a teljes összegzés.
	- `lang`: nyelvkód (`en`, `es`, `fr`, `hu`, `zh`), ami a prompt nyelvét állítja.
- **Működés**:
	- `DEEPSEEK_API_KEY` env var beolvasása; hiány esetén felhasználóbarát hiba.
	- A rendszeradatokat egy tömbösített, “tale” jellegű szövegbe rendezi.
	- `reqwest::Client` 60s timeouttal.
	- POST `https://api.deepseek.com/chat/completions`, JSON body: `model=deepseek-chat`, `messages=[{role:user,content:...}]`, `temperature=0.7`.
	- HTTP hibánál a teljes response body visszajön a hibaüzenetben.
	- JSON parse után az első `choices[0].message.content` a kimenet.
- **Kimenet**: sima szöveg (a prompt kifejezetten kéri, hogy *ne* legyen markdown).
- **Hibák**: hiányzó API kulcs, hálózat, nem‑2xx, JSON parse, üres `choices`.
- **Megjegyzés**: a frontend oldalán van cooldown (60s), de a backend nem enforce-ol rate limitet.

### `fn ls_get_entitlements(app: AppHandle) -> Result<lemonsqueezy::Entitlements, String>`

- **Tauri parancs**.
- **Felelősség**: lokális licenc cache alapján “jogosultság” visszaadása (aktív-e, lejárat, email, last4).
- **Működés**: `lemonsqueezy::get_entitlements(&app)`.

### `async fn ls_activate_license(app: AppHandle, license_key: String, instance_name: String) -> Result<lemonsqueezy::Entitlements, String>`

- **Tauri parancs**.
- **Felelősség**: licenc aktiválása a LemonSqueezy API-n.
- **Működés**: `lemonsqueezy::activate_license(&app, license_key, instance_name).await`.
- **Mellékhatás**: `license_state.json` frissítése az app config könyvtárban.

### `async fn ls_refresh_entitlements(app: AppHandle) -> Result<lemonsqueezy::Entitlements, String>`

- **Tauri parancs**.
- **Felelősség**: licenc állapot validálása/frissítése a LemonSqueezy API-val.
- **Működés**: `lemonsqueezy::refresh_entitlements(&app).await`.

### `async fn ls_deactivate_license(app: AppHandle) -> Result<(), String>`

- **Tauri parancs**.
- **Felelősség**: licenc deaktiválása (ha van `instance_id`), majd lokális state törlése.

### `pub fn run()`

- **Felelősség**: Tauri app felépítése és futtatása.
- **Működés**:
	- `.env` betöltés (`dotenvy::dotenv().ok()`).
	- `Monitor` state regisztrálása: `manage(Monitor(Arc<Mutex<MonitorState::new()>>))`.
	- `invoke_handler` regisztrálja az összes Tauri parancsot, plusz a monitor modul parancsait.
- **Mellékhatás**: GUI futtatása.

---

## `src-tauri/src/fetch.rs`

### `fn detect_gpu_manufacturer(name: &str) -> String`

- **Felelősség**: GPU név alapján gyártó becslése (`NVIDIA` / `AMD` / `Intel` / `Unknown`).
- **Működés**: upper-case substring keresések (GeForce/Quadro/RTX/GTX, Radeon/RX, Iris/UHD/HD Graphics, stb.).
- **Kimenet**: gyártó string.

### `pub fn get_cpu_info() -> CpuInfo`

- **Felelősség**: CPU architektúra, logikai processzorok száma, márkanév.
- **Működés**:
	- `GetSystemInfo` → `dwNumberOfProcessors`, `wProcessorArchitecture`.
	- CPU brand: `get_cpu_brand()` (x86_64 esetén CPUID, különben `Unknown`).
- **Kimenet**: `CpuInfo { architecture, processors, name }`.

### `unsafe fn get_cpu_brand() -> String` (`cfg(target_arch = "x86_64")`)

- **Felelősség**: CPUID leaf-ekből a 48 bájtos brand string kiolvasása.
- **Működés**: `__cpuid(0x80000002..0x80000004)`; byte tömb összeállítása; `sanitize_cpu_brand`.
- **Biztonság**: `unsafe`, mert arch intrinsics.

### `unsafe fn get_cpu_brand() -> String` (`cfg(not(target_arch = "x86_64"))`)

- **Felelősség**: nem x86_64 arch-on fallback.
- **Kimenet**: `"Unknown"`.

### `fn sanitize_cpu_brand(raw: &[u8]) -> String`

- **Felelősség**: CPUID-ból kapott bájtok “emberi” stringgé alakítása.
- **Működés**: null terminátor keresés, nem‑printable karakterek szűrése, UTF‑8 lossy konverzió, trim.

### `pub fn get_memory_info() -> MemoryInfo`

- **Felelősség**: fizikai RAM total/free GB.
- **Működés**: `GlobalMemoryStatusEx`; `ullTotalPhys`, `ullAvailPhys`.
- **Hibakezelés**: API fail → 0.0/0.0.

### `pub fn get_os_info() -> String`

- **Felelősség**: Windows verzió és build szám megbízhatóbban, mint a “manifest nélküli” standard API-k.
- **Működés**:
	- `LoadLibraryW("ntdll.dll")`.
	- `GetProcAddress("RtlGetVersion")`.
	- `RTL_OSVERSIONINFOW` kitöltése.
	- Windows 11 detektálás: major=10 és build>=22000.
- **Kimenet**: pl. `Windows 11.x (Build 226xx)`.

### `pub fn get_gpu_info() -> Vec<GpuInfo>`

- **Felelősség**: GPU-k listázása név + VRAM MB + gyártó.
- **Működés**:
	- Elsődleges: DXGI (`CreateDXGIFactory1` + `EnumAdapters1` + `GetDesc1`).
	- Szoftver adapterek kihagyása (`DXGI_ADAPTER_FLAG_SOFTWARE`).
	- VRAM: dedicated vs shared; integrált GPU esetén a nagyobb érték preferált.
	- Fallback: `EnumDisplayDevicesW` aktív display device-ok.
- **Megjegyzés**: COM init/uninit best-effort.

### `pub fn get_disk_info() -> DiskInfo`

- **Felelősség**: C: meghajtó total/free GB.
- **Működés**: `GetDiskFreeSpaceExW("C:\\")`.
- **Limitáció**: jelenleg fixen C:.

### `pub fn get_network_info() -> Vec<String>`

- **Felelősség**: aktív (OperStatusUp) adapterek “FriendlyName” listája.
- **Működés**: `GetAdaptersAddresses` és láncolt lista bejárása.
- **Limitáció**: csak név, nincs IP/mac.

### `pub fn get_system_info() -> SystemInfoData`

- **Felelősség**: hostname + username.
- **Működés**: `GetComputerNameExW(COMPUTER_NAME_FORMAT(0))`, username env varból (`USERNAME` vagy `USER`).

---

## `src-tauri/src/ps.rs`

### `pub fn run_powershell(script: &str, timeout: Duration) -> Result<PsOutput, String>`

- **Felelősség**: PowerShell futtatása megbízható timeouttal, stdout/stderr begyűjtéssel.
- **Működés**:
	- `powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command <script>`.
	- `wait_timeout` crate: ha túlfut, process kill és hiba.
	- stdout/stderr olvasás (trim).
	- Nem‑0 exit code esetén: előbb stderr, különben stdout, különben általános státusz.
- **Kimenet**: `PsOutput { stdout, stderr }`.
- **Hibák**: spawn fail, timeout, IO read fail, non‑success exit.

---

## `src-tauri/src/discovery.rs`

### `pub fn discover_hosts(options: DiscoveryOptions, timeout: Duration) -> Result<Vec<DiscoveredHost>, String>`

- **Felelősség**: LAN hostok best‑effort felderítése.
- **Bemenet**:
	- `max_hosts`: limit (default 128).
	- `include_neighbors`: `Get-NetNeighbor` használata.
	- `ping_sweep`: `/24` ping sweep.
- **Működés (PowerShell)**:
	- `Get-NetNeighbor -AddressFamily IPv4` → Reachable, nem 169.254/127.0.0.1/multicast/broadcast.
	- Opcionális ping sweep: választ egy helyi IPv4 címet `PrefixLength >= 24`, majd `Test-Connection` 1s timeouttal 1..254.
	- Deduplikálás IP szerint; `Select-Object -First max_hosts`.
	- JSON output; 1 elemnél PS objektum, többnél tömb → Rust oldalon mindkettő kezelve.
- **Kimenet**: `Vec<DiscoveredHost { ip, source }>`.
- **Hibák**: PowerShell hiba, JSON parse hiba.

---

## `src-tauri/src/diagnostics.rs`

### `pub fn diagnose_host(ip: &str, timeout: Duration) -> RemoteSystemInfo`

- **Felelősség**: egy távoli host Windows rendszeradatainak lekérdezése (WMI/CIM DCOM-on).
- **Bemenet**: `ip` és maximum futási idő.
- **Előszűrés**:
	- multicast/broadcast címek (224–239.*, 255.255.255.255, `*.255`) kihagyása.
	- gyors preflight: TCP/135 connect (RPC/DCOM) 800ms alatt; ha nem elérhető, kihagyás.
- **Működés (PowerShell)**:
	- `New-CimSessionOption -Protocol Dcom` + `New-CimSession -ComputerName <ip>`.
	- `Win32_ComputerSystem`, `Win32_OperatingSystem`, `Win32_Processor`, `Win32_LogicalDisk (DriveType=3)`, `Win32_VideoController`.
	- Disk total/free összeadás; RAM total/free GB-ra.
	- JSON compress output.
	- `finally` blokk: CIM session törlés.
- **Kimenet**: `RemoteSystemInfo` (több mező `Option`, plusz `error`).
- **Hibakezelés**:
	- Üres/stdout `null` → “No output from diagnostics”.
	- JSON parse fail → `error` mezőbe részletes üzenet.
	- PowerShell fail → `error`.

---

## `src-tauri/src/export_excel.rs`

### `fn to_err(e: XlsxError) -> String`

- **Felelősség**: `rust_xlsxwriter` hibák egységes stringgé konvertálása.

### `pub fn write_diagnostics_xlsx(path: &Path, rows: &[RemoteSystemInfo]) -> Result<(), String>`

- **Felelősség**: távoli diagnosztika eredmények exportja `.xlsx` fájlba.
- **Működés**:
	- Workbook + worksheet (`Diagnostics`).
	- Header sor félkövér, középre igazítva.
	- Soronként: string mezők + opcionális numerikus mezők (logical cpu, mem/disk GB), GPU-k vesszővel joinolva.
	- `autofit()` a szélességekhez.
	- `workbook.save(path)`.
- **Hibák**: minden xlsx hiba `XLSX export error: ...` formátumban.

---

## `src-tauri/src/lemonsqueezy.rs`

### Modell

- `Entitlements`: amit a UI használ (active/status/expires/email/last4).
- `LicenseState`: lokális cache (teljes license_key + instance_id + meta + utolsó ellenőrzés).

### `fn is_active_status(status: &str) -> bool`

- **Felelősség**: LemonSqueezy státusz string “aktívnak” minősítése.
- **Megjegyzés**: a komment szerint státuszok: `inactive`, `active`, `expired`, `disabled`. A kód jelenleg `active` és `inactive` esetén is true-t ad, miközben explicit kizárja az `expired`/`disabled` értéket.

### `fn mask_last4(key: &str) -> Option<String>`

- **Felelősség**: a licenckulcs utolsó 4 karakterének visszaadása (UI-ban megjelenítéshez).
- **Hiba**: 4 karakternél rövidebb → `None`.

### `fn app_config_path(app: &AppHandle) -> Result<PathBuf, String>`

- **Felelősség**: app-specifikus config könyvtár (`app_config_dir()/wfetch`).
- **Működés**: Tauri path API.

### `fn license_state_path(app: &AppHandle) -> Result<PathBuf, String>`

- **Felelősség**: `license_state.json` teljes útvonal.

### `fn read_state(app: &AppHandle) -> Result<Option<LicenseState>, String>`

- **Felelősség**: lokális license state beolvasása.
- **Működés**: ha nincs fájl → `Ok(None)`; egyébként `read_to_string` + JSON parse.

### `fn write_state(app: &AppHandle, state: &LicenseState) -> Result<(), String>`

- **Felelősség**: license state mentése pretty JSON-ként.
- **Működés**: config dir `create_dir_all`, majd file write.

### `fn delete_state(app: &AppHandle) -> Result<(), String>`

- **Felelősség**: lokális state törlése.

### `fn entitlements_from_state(state: Option<&LicenseState>) -> Entitlements`

- **Felelősség**: cache rekordból UI-barát `Entitlements` képzése.
- **Működés**: `active` számítása `status` alapján, last4 számítása.

### `pub fn get_entitlements(app: &AppHandle) -> Result<Entitlements, String>`

- **Felelősség**: gyors, offline‑barát jogosultság lekérdezés (csak lokális fájlból).

### `pub async fn activate_license(app: &AppHandle, license_key: String, instance_name: String) -> Result<Entitlements, String>`

- **Felelősség**: licenc aktiválása.
- **Működés**:
	- POST `https://api.lemonsqueezy.com/v1/licenses/activate` form data-val.
	- Nem‑2xx esetén: teljes body hibaüzenet.
	- JSON parse; `activated` flag ellenőrzés.
	- `instance_id` eltárolása (ha jön).
	- `last_checked_unix_ms` frissítése.
	- lokális `license_state.json` mentése.
- **Kimenet**: `Entitlements`.

### `pub async fn refresh_entitlements(app: &AppHandle) -> Result<Entitlements, String>`

- **Felelősség**: cache frissítése/validálása.
- **Működés**:
	- Ha nincs lokális state → inaktív entitlements.
	- POST `.../validate` licenckulccsal (+ instance_id ha van).
	- `valid=false` esetén: state `status=invalid` és hibával visszatér (UI üzenethez).
	- `valid=true` esetén: state frissítése a válasz alapján, majd `Entitlements`.

### `pub async fn deactivate_license(app: &AppHandle) -> Result<(), String>`

- **Felelősség**: licenc deaktiválása és lokális törlés.
- **Működés**:
	- Ha nincs state → ok.
	- Ha van `instance_id`: POST `.../deactivate`.
	- Ha a távoli deaktiválás jelez hibát, a lokális fájl megmarad (újrapróbálható).
	- Siker után `delete_state`.

---

## `src-tauri/src/monitor.rs`

### Adatmodellek

- `MonitorSample`: timestamp + CPU% + memória (used/total GB).
- `ProcessSnapshot`: PID + process név + CPU% + working set memória.
- `IncidentSnapshot`: incident azonosító + timestamp + total CPU/mem + top process lista.

### `impl MonitorState { pub fn new() -> Self }`

- **Felelősség**: monitor alapállapot.
- **Defaultok**:
	- `enabled=false`
	- `sensitivity=85`
	- `samples=[]`, `incidents=[]`, `running_handle=None`

### `fn filetime_to_u64(ft: FILETIME) -> u64`

- **Felelősség**: Windows `FILETIME` (hi/lo) 64 bites tické alakítása.

### `fn get_cpu_load(prev_idle: u64, prev_kernel: u64, prev_user: u64) -> (f32, u64, u64, u64)`

- **Felelősség**: rendszer CPU kihasználtság számítása a `GetSystemTimes` deltakból.
- **Kimenet**:
	- `cpu_percent` 0..100 clampelve
	- új idle/kernel/user tick értékek a következő iterációhoz

### `fn get_memory_usage() -> (f32, f32)`

- **Felelősség**: memória used/total GB.
- **Működés**: `GlobalMemoryStatusEx`.

### `fn get_process_list() -> HashMap<u32, (String, u64, u64)>`

- **Felelősség**: pillanatnyi process lista CPU időkkel.
- **Működés**:
	- ToolHelp snapshot: `CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS)`.
	- `Process32First/Next`.
	- PID>4 szűrés.
	- `OpenProcess(PROCESS_QUERY_INFORMATION|PROCESS_VM_READ)`.
	- `GetProcessTimes` → kernel/user FILETIME tick.
- **Kimenet**: PID → (name, kernel_ticks, user_ticks).

### `async fn capture_detailed_snapshot() -> Vec<ProcessSnapshot>`

- **Felelősség**: top 10 process CPU használat becslése rövid időablakon.
- **Működés**:
	- két mintavétel 500ms különbséggel (`t1`, `t2`).
	- delta kernel+user tick alapján “load unit”.
	- memória: `GetProcessMemoryInfo` WorkingSetSize.
	- CPU% normalizálás: $\text{cpu\_percent} = \frac{\Delta\text{ticks}}{5\cdot 10^6} \cdot \frac{100}{\text{cpu\_count}}$.
	- rendezés csökkenő CPU szerint; top 10.
- **Megjegyzés**: rövid ablak miatt “tüskék” jól kijönnek, de nem hosszú távú átlag.

### `pub fn start_monitor_loop(app: AppHandle, state: Arc<Mutex<MonitorState>>)`

- **Felelősség**: háttér task indítása, ami 2 másodpercenként sample-t vesz.
- **Működés**:
	- `GetSystemTimes` inicializáló mintavétel.
	- loop: sleep(2s) → CPU% + memória.
	- sample ring buffer (max 60 db ~ 2 perc).
	- ha CPU > sensitivity 3 egymást követő mintán → incident.
	- incident esetén `capture_detailed_snapshot()` + `app.emit("monitor-incident", incident)`.
	- leállás: ha `enabled` false lesz, a loop kilép, `running_handle=None`.

### `pub fn set_monitor_state(app: AppHandle, state: tauri::State<'_, Monitor>, enabled: bool)`

- **Tauri parancs**.
- **Felelősség**: monitor ki/be kapcsolása.
- **Működés**:
	- state lock: `enabled` beállítása.
	- ha bekapcsolás és nincs futó handle → `start_monitor_loop`.
- **Megjegyzés**: a loop “önleáll”, ha `enabled` false.

### `pub fn set_monitor_sensitivity(state: tauri::State<'_, Monitor>, threshold: u8)`

- **Tauri parancs**.
- **Felelősség**: küszöbérték állítása (százalék).

### `pub fn get_monitor_incidents(state: tauri::State<'_, Monitor>) -> Vec<IncidentSnapshot>`

- **Tauri parancs**.
- **Felelősség**: utolsó incidentek (max ~10) lekérése UI számára.

---

# Frontend (React)

## `src/main.jsx`

### React root render

- `ReactDOM.createRoot(...).render(...)`: a `App` komponens mountolása `StrictMode` alatt.

---

## `src/translations.js`

### `export const t = (key, lang = "en", params = {}) => { ... }`

- **Felelősség**: egyszerű i18n key‑path fordító.
- **Bemenet**:
	- `key`: ponttal tagolt kulcs (pl. `settings.subscription.title`).
	- `lang`: nyelv kód.
	- `params`: template paraméterek (pl. `{{seconds}}`).
- **Működés**:
	- kulcs bejárása `translations[lang]` objektumban.
	- fallback angolra, ha hiányzik.
	- string esetén `{{param}}` cserék regex-szel.
- **Kimenet**: fordított string (vagy a key fallbackként).

---

## `src/App.jsx`

### `function App()`

- **Felelősség**: teljes UI állapotgép: rendszerinfo betöltés, AI elemzés UX (progress + cooldown), licenc kezelő nézetek, monitor nézet, admin network diag.
- **Adatforrások**:
	- Tauri backend `invoke()` parancsok.
	- monitor események: `listen("monitor-incident", ...)`.
	- `localStorage`: language, theme, saveTheme, monitorEnabled, monitorSensitivity, devUnlocked.

#### Fontosabb belső (névvel rendelkező) függvények

##### `const applyTheme = (themeName) => { ... }`

- **Felelősség**: kiválasztott témához tartozó CSS változók beállítása (`document.documentElement.style.setProperty`).
- **Bemenet**: `themeName` (`system`, `light`, `dark`, `cherry`, `midnight`).
- **Működés**: theme mapből kiválaszt, fallback `system`.
- **Mellékhatás**: globális CSS változók módosítása (azonnali UI átállás).
- **Megjegyzés**: előfizetés nélkül a nem-system témák le vannak tiltva.

##### `const nudgeStory = async () => { ... }`

- **Felelősség**: AI elemzés triggerelése.
- **Fő szabályok**:
	- csak ha van `bits` és nincs cooldown (`ticks===0`).
	- ha nincs előfizetés (vagy még töltődik) → UI hibaüzenet.
	- futás közben progress “szimuláció” (`analyzePercent`) 99%-ig.
	- siker/hiba után 60s cooldown (`pauseUntil = now + 60000`).
- **Backend hívás**: `invoke("send_to_ai", { systemInfo: bits, lang: language })`.

##### `const navigateTo = (page) => { ... }`

- **Felelősség**: egyszerű oldalváltás animációval.
- **Működés**: `isExiting=true`, 300ms után `currentPage=page`, majd vissza.

##### Licenc műveletek (a Settings/Subscription nézetben)

- `activateLicense`: `ls_activate_license` hívás a `licenseKey` + `system.hostname` alapján. Dev buildben két “cheat code” is van:
	- `bestMilioSupportEver` → `devUnlocked=true`
	- `worstMilioSupportEver` → `devUnlocked=false`
- `refreshLicense`: `ls_refresh_entitlements`.
- `deactivateLicense`: `ls_deactivate_license` (devUnlocked esetén csak local flag törlés).
- `openCheckout`: `openUrl(checkoutUrl)` (ha nincs URL → lokalizált hiba).

##### Admin: Network Diagnostics

- gombnyomásra `invoke("scan_network_and_export_excel", { options: ... })`.
- a result UI-ban megjelenik (output path + statisztika).

### `function InfoCard({ title, children, id })`

- **Felelősség**: “glass card” UI keret egységes címkével.
- **Bemenet**: `title`, `children`, opcionális `id` (anchor/teszt).

### `function InfoRow({ label, value, extra })`

- **Felelősség**: kulcs‑érték sor megjelenítése.
- **Megjegyzés**: `extra` esetén zárójelben jelenik meg.

### `function ProgressBar({ percent, color })`

- **Felelősség**: százalékos sáv megjelenítése.
- **Bemenet**:
	- `percent`: 0..100.
	- `color`: jelenleg `blue` esetén kék gradient, más esetben lila/piros gradient.

### `function FadingText({ text, startDelay = 0, step = 20 })`

- **Felelősség**: AI válasz “gépelős/elfakulós” animációja karakterenként.
- **Működés**:
	- a stringet karakterekre bontja.
	- minden karakter külön span, `animationDelay = startDelay + i*step`.
- **Megjegyzés**: space esetén non‑breaking space (`\u00A0`).

---

## Tipikus hibák / troubleshooting

- **AI elemzés nem megy**: ellenőrizd a `DEEPSEEK_API_KEY` értékét (backend oldal), és hogy van-e internet elérés.
- **LAN scan nem talál hostokat**: generálj LAN forgalmat, engedélyezd ICMP-t, illetve a `Get-NetNeighbor` eredménye sokszor csak “látott” gépeket ad.
- **Távoli diagnosztika hibázik**: tipikusan:
	- RPC/DCOM blokkolt (TCP/135),
	- WMI jogosultság hiány,
	- tűzfal szabályok,
	- a célgép nem Windows.
- **GPU/Network üres**: egyes Windows konfigurációkon a DXGI vagy adapter enumeráció késhet vagy fail-elhet; a UI ilyenkor üres listát mutat.

## Fejlesztői megjegyzések

- A Tauri config a `src-tauri/tauri.conf.json` fájlban van.
- Vite server port fix: 1420 (`vite.config.js`).
- A háttér monitor eseményt `monitor-incident` néven küldi a backend.

empty