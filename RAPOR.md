# ÜniCraft Launcher v2.5.6: Güvenlik İddiaları ve Gerçekler (Topluluk Teknik Denetim Raporu)

Tarih: 21 Kasım 2026  
İncelenen paket: `UniCraft Launcher Setup 2.5.6.exe`, SHA-256 özeti `da19665407a2546fa3aa576949563ae4e84d4f3cfa3982a59924ee142b477ba1`.  
İncelenen kaynaklar: Dağıtılan `app.asar` kodları, `package.json`, `unicraftmc.com` web arayüzü ve API uç noktaları.  
Dinamik kum havuzu kaydı: `https://tria.ge/261121-arp23azs2k/behavioral1`, tehdit puanı 7/10.

## 1. Yönetici Özeti

ÜniCraft platformu, dağıttığı istemci yazılımını hile korumalı özel bir başlatıcı olarak sunmaktadır. Geliştirici ekibin oyunculara yaptığı açıklamalarda, dinamik analiz araçlarında ortaya çıkan yüksek tehdit puanlarının BattlEye veya EasyAntiCheat benzeri güvenlik mekanizmalarından kaynaklandığı, kod imzasının ise ticari sertifika maliyetleri nedeniyle devre dışı bırakıldığı belirtilmektedir.

Kaynak kodları, ağ trafiği ve istemci veri akışları üzerinden yapılan bu bağımsız teknik denetim, söz konusu savunmaların teknik temellerini incelemektedir. İnceleme sonucunda istemcinin gelişmiş bir hile engelleme altyapısından ziyade; işletim sistemi izinlerini bozan, kullanıcının kişisel dosyalarını silen, gizlilik politikasındaki beyanların aksine arka plan süreçlerini izleyen ve temel imza denetimlerini atlayan yöntemler barındırdığı tespit edilmiştir.

## 2. Dağıtım ve Altyapı Mimarisi

İstemcinin dağıtımında tutarsız bir erişim denetimi mimarisi uygulanmaktadır.

Web ön yüzünde, `unicraftmc.com` sitesindeki indirme bağlantısı oturum açmış kullanıcılar için `POST https://api.unicraftmc.com/v1/launcher/download-ticket` çağrısı yaparak tek kullanımlık bilet üretmektedir.

Buna karşın güncelleme sunucusu tarafında, `updates.unicraftmc.com` üzerindeki `latest.yml` ve 77.6 MB boyutundaki kurulum dosyası doğrudan erişime açıktır. Herhangi bir bilet veya kimlik doğrulama zorunluluğu olmaksızın indirilebilmektedir. Ön yüzdeki bilet mekanizması ile CDN üzerindeki doğrudan erişim arasındaki bu tezat, dağıtım altyapısındaki erişim kontrolü eksikliğini göstermektedir.

Altyapı geçmişi incelendiğinde, istemci kodundaki `_normalizeModUrl` fonksiyonunda geçen `updates.gogusler.de` adresinin platformun eski sunucusu olduğu anlaşılmaktadır. İlgili altyapı, yani `unicraft.sbs` ve `gogusler.de` alan adları, 19 Nisan 2026 tarihinde Hostinger Abuse birimi tarafından incelenerek Hizmet Şartları ihlali gerekçesiyle resmi olarak askıya alınmıştır. İlgili işlem Hostinger Bilet No QTB-KSPPZ-122 altında kayıtlıdır. Koddaki URL yönlendirme mantığı, askıya alınan bu sunucudan yeni adrese yani `updates.unicraftmc.com` alan adına geçiş sürecinde eklenmiştir. Ayrıca 2 Mayıs 2026 tarihinde Cloudflare Trust and Safety birimi tarafından `unicraftmc.com` alan adına yönelik güvenlik bildirimi üzerine URL kısıtlaması uygulandığı resmi bilet kaydıyla sabittir. İlgili işlem Cloudflare Bilet No d3778c262bc4d08d altında belgelenmiştir:

```javascript
// main.js (Satır 1919)
function _normalizeModUrl(url) {
  if (typeof url !== "string") return url;
  return url.replace(/^https?:\/\/updates\.gogusler\.de\//i, "https://updates.unicraftmc.com/");
}
```

## 3. Teknik Bulgular ve Güvenlik Analizi

### 3.1. Güncelleme İmza Doğrulamasının İptali ve Sertifika Gerekçesi (CWE-347 / CWE-494)

Ekip yetkilileri imza denetiminin kapatılmasını şu ifadelerle açıklamıştır: *"Signature bypass: Launcher code-signed değil, sertifika pahalı, gönüllü öğrenci projesiyiz. Güncelleme yine bizim kendi domain'imizden HTTPS ile geliyor."*

Bu açıklama iki farklı güvenlik katmanını birbirine karıştırmaktadır. Windows işletim sistemi düzeyinde güven sağlayan ticari Authenticode sertifikası ile uygulamanın indirdiği güncellemeyi asimetrik şifrelemeyle doğrulaması ayrı konulardır. Bir yazılımın kendi güncelleme paketini doğrulaması için ticari bir sertifika otoritesine ödeme yapmasına gerek yoktur. Node.js içindeki yerleşik `crypto` modülü kullanılarak Ed25519 veya RSA anahtar çiftiyle tamamen ücretsiz ve bağımsız bir imza doğrulama mekanizması kurulabilir.

ÜniCraft geliştiricileri bu amaçla kendi özel kontrol iskeletini oluşturmuş, ancak `package.json` dosyasındaki genel anahtar alanını boş bırakmıştır:

```json
"unicraftUpdatePublicKey": ""
```

Kod tarafında ise yerleşik imza doğrulama fonksiyonları iptal edilmiş ve boş anahtar görüldüğünde doğrulama adımı işletilmeden geçilmiştir:

```javascript
// main.js (Satır 376 - 386)
autoUpdater.verifySignature = async () => null;
autoUpdater.verifyUpdateCodeSignature = () => Promise.resolve(null);

// main.js (Satır 51 - 56)
async function verifyDownloadedUpdate(updateInfo) {
  if (!UPDATE_PUBLIC_KEY) {
    console.warn("[updater] unicraftUpdatePublicKey tanımlı değil; imza doğrulaması atlandı.");
    return;
  }
}
```

Geliştiricilerin özel bir doğrulama fonksiyonu yazıp genel anahtarı boş bırakması, sertifika maliyetinden bağımsız bir mimari tercihtir. Yalnızca HTTPS bağlantısına güvenmek yeterli değildir. Güncelleme sunucusunun veya Cloudflare hesabının ele geçirilmesi durumunda, istemcilere gönderilecek zararlı bir güncelleme imza kontrolü yapılmadan doğrudan çalıştırılacaktır. Bu durum CWE-347 ve CWE-494 kapsamında açık bir tedarik zinciri zafiyetidir.

### 3.2. Gizlilik Beyanı ile Çelişen Süreç Taraması (CWE-359)

Geliştirici ekip, Tria.ge kum havuzundaki 7/10 tehdit puanını savunurken şu iddiada bulunmuştur: *"Her anti-cheat orada yüksek puan alır, BattlEye, EAC bile. Sandbox süreç tarama ve HWID kombosunu görünce refleks olarak flag'liyor."*

Ancak profesyonel hile koruma sistemleri ile ÜniCraft arasındaki temel fark resmi kullanıcı taahhüdüdür. ÜniCraft'ın `https://unicraftmc.com/gizlilik-politikasi` adresindeki resmi metninde kullanıcılara şu açık beyan verilmektedir:

> *"Anti-cheat: yalnızca onaylı modların yüklü olduğunu teyit etmek için. Modlarının içeriği veya oyun içi davranışın okunmaz, yalnızca dosya hash'i karşılaştırılır."*
> *"Launcher şunları toplamaz: klavye/fare girdileri, ekran görüntüsü, dosya sisteminin tamamı, kişisel belgeler, tarayıcı geçmişi, diğer oyunların verisi..."*

Sitede yalnızca mod hash kontrolü yapıldığı açıkça taahhüt edilmesine rağmen, `main.js` içinde her 60 saniyede bir Windows `tasklist` komutu çalıştırılmakta ve çalışan tüm süreçler taranmaktadır:

```javascript
// main.js (Satır 2150 - 2165)
const targetProcesses = [
  "cheatengine", "cheat engine", "x64dbg", "x32dbg", "ollydbg",
  "windbg", "radare2", "processhacker", "artmoney",
  "wireshark", "fiddler", "charlesproxy", "charles proxy", "mitmproxy"
];

exec("tasklist /fo csv /nh", { timeout: 5000 }, (err, stdout) => {
  const running = stdout.toLowerCase();
  for (const proc of targetProcesses) {
    if (running.includes(proc)) {
      reportSecurityEvent("cheat_process_detected", { process: proc });
      break;
    }
  }
});
```

Wireshark, Fiddler, Charles Proxy ve Process Hacker gibi meşru ağ analizi ve hata ayıklama araçları hile olarak etiketlenmekte; kullanıcı adı ve zaman damgasıyla birlikte `cheat_process_detected` olayı olarak sunucuya raporlanmaktadır. Kullanıcıya yalnızca dosya hash'i kontrol edildiği söylenirken arka planda işletim sistemi süreçlerinin izlenmesi ve kaydedilmesi, CWE-359 kapsamında aydınlatma yükümlülüğü ve gizlilik ihlalidir.

### 3.3. Dizin Seçiminde Kişisel Mod Dosyalarının Onaysız Silinmesi

İstemci, mod dizinini denetleyen bir bekçi döngüsü barındırmaktadır:

```javascript
// main.js (Satır 1475 - 1506)
function startModGuard(modsDir, allowedList) {
  const allowed = new Set([...allowedList].map(x => x.toLowerCase()));
  function scan() {
    if (!active) return;
    try {
      const files = fs.readdirSync(modsDir);
      for (const file of files) {
        if (!file.toLowerCase().endsWith(".jar")) continue;
        if (!allowed.has(file.toLowerCase())) {
          fs.unlinkSync(path.join(modsDir, file));
          reportSecurityEvent("foreign_jar_detected", { file, action: "deleted" });
        }
      }
    } catch {}
    if (active) setTimeout(scan, 100);
  }
  scan();
}
```

Standart başlatıcılar kendi mod paketlerini izole profiller altında tutar. ÜniCraft ise kullanıcının sistemdeki herhangi bir oyun klasörünü seçmesine olanak tanımaktadır. Bir kullanıcı mevcut `.minecraft` dizinini oyun konumu olarak belirlediğinde, `startModGuard` kullanıcının diğer sunucularda kullandığı kişisel mod dosyalarını herhangi bir onay veya uyarı penceresi sunmaksızın diskten kalıcı olarak silmektedir.

### 3.4. Windows NTFS Klasör İzinleri Manipülasyonu ve Kilit Riski (CWE-732 / CWE-459)

Mod dizinine dışarıdan dosya eklenmesini engellemek amacıyla Windows üzerinde `icacls` komutu yürütülmektedir:

```javascript
// main.js (Satır 1436 - 1446)
execFile("icacls", [modsDir, "/deny", principal + ":(CI)(WD,AD)"], { shell: false });
```

Bu komut dosya silme yetkisini değil, klasöre dosya yazma ve ekleme yetkilerini kesmektedir. Oyun kapatıldığında izinlerin `/remove:d` parametresiyle geri verilmesi hedeflenmiştir. Ancak oyun çöktüğünde veya süreç görev yöneticisinden sonlandırıldığında temizlik adımı çalışmamakta; kilit açık kalarak kullanıcının kendi dizinine dosya yazmasını engellemektedir. Bu yöntem Linux veya macOS sistemlerinde uygulanmamakta, yalnızca Windows kullanıcılarının dosya sistemi üzerinde kalıcı kilit riski oluşturmaktadır.

### 3.5. Öğrenci Kimlik Kartlarının Genel Geri Bildirim Kanalında İşlenmesi (6698 SK md. 12)

Platformun `/dogrula-manuel` sayfasında öğrencilerden Ad Soyad, Öğrenci No, Üniversite ve öğrenci kimlik kartı fotoğrafı toplanmaktadır. Fotoğraf istemci tarafında Base64 formatına çevrilmektedir.

Toplanan kimlik kartları izole bir doğrulama modülü yerine, genel destek ve hata bildirimlerinin toplandığı `/v1/feedback` uç noktasına düz metin içine gömülerek iletilmektedir:

```javascript
// dogrula-manuel (Satır 810 - 825)
const mainBody = {
  subject: subject,
  message: textMsg + "

PHOTO:
" + photoB64,
  category: "manual_verification",
  turnstileToken: turnstileToken,
};
const r = await fetch(API + "/v1/feedback", {
  method: "POST", headers, body: JSON.stringify(mainBody),
});
```

Vercel üzerinde barındırılan `/yonetim` tek sayfa uygulamasının kaynak kodları incelendiğinde, bu fotoğrafların geri bildirim listesi içerisinden regex ile ayrıştırılarak ön yüz arayüzüne basıldığı görülmektedir:

```javascript
// yonetim (Satır 3740 - 3755)
const photoMatch = raw.match(/
PHOTO:
?(data:image\/[^\s][\s\S]*)/);
if (photoMatch) {
  info.photoData = photoMatch[1].trim();
}
```

T.C. kimlik numarası, okul numarası ve kimlik fotoğrafı içeren belgelerin genel bir geri bildirim tablosu içerisinde uygulama düzeyinde şifreleme ve erişim izolasyonu olmaksızın işlenmesi, 6698 sayılı Kişisel Verilerin Korunması Kanunu 12. maddesi kapsamındaki teknik tedbir ve veri güvenliği ilkeleri açısından ciddi risk ve uyumsuzluk oluşturmaktadır.

### 3.6. İstemci Tarafı Kontrolleri ve Kullanıcı Ayarlarına Müdahale

İstemcideki güvenlik mekanizmaları istemci tarafında kolaylıkla manipüle edilebilen mantıklar üzerine kuruludur:

Donanım kimliği tespiti doğrudan diskteki `hwid-cache.json` dosyasına dayanmaktadır:

```javascript
// main.js (Satır 905 - 915)
async function getOrReadHwid() {
  try {
    if (fs.existsSync(HWID_CACHE_FILE)) {
      const cached = JSON.parse(fs.readFileSync(HWID_CACHE_FILE, "utf8"));
      if (cached && typeof cached.hwid === "string" && cached.hwid.length >= 32) {
        return cached.hwid;
      }
    }
  } catch {}
```

Anakart UUID değeri ilk açılışta alınıp `hwid-cache.json` dosyasına yazılmakta, sonraki açılışlarda donanım tekrar sorgulanmamaktadır. Bu dosyadaki hash değeri değiştirildiğinde sunucu bunu yeni bir bilgisayar olarak kabul etmekte ve cihaz yasağı geçersiz kalmaktadır.

Java çalışma ortamı denetiminde `javaw.exe` parmak izi sunucu tarafından doğrulanmamaktadır. Diske ilk bırakılan JVM dosyasının boyut ve değiştirilme tarihi bilgisi temel alınmaktadır (Satır 3270 - 3310).

Çoklu istemci açılışında kilit çakışması yaşandığında Node.js olay döngüsünü senkron bekletmek için en fazla 3 tur `ping` komutu çalıştırılmaktadır:

```javascript
// main.js (Satır 226 - 234)
if (err.code === "EPERM" || err.code === "EACCES" || err.code === "EBUSY") {
  try {
    require("child_process").execSync("ping -n 1 -w 80 127.0.0.1 >nul", {
      stdio: "ignore"
    });
  } catch {}
  continue;
}
```

İstemci, `servers.dat` dosyasında `play.unicraftmc.com` kaydı bulunmadığında kullanıcının mevcut tüm sunucu listesini silerek tek sunuculu yeni bir dosya oluşturmaktadır:

```javascript
// main.js (Satır 2702 - 2719)
async function ensureUniCraftServer(gameDir) {
  const fsExtra = require("fs-extra");
  const serversDatPath = path.join(gameDir, "servers.dat");
  const serverIp = "play.unicraftmc.com";
  if (await fsExtra.pathExists(serversDatPath)) {
    try {
      const buf = await fsExtra.readFile(serversDatPath);
      if (buf.includes(Buffer.from(serverIp, "utf8"))) return;
    } catch {}
  }
  await fsExtra.ensureDir(gameDir);
  await fsExtra.writeFile(serversDatPath, buildServersDat([{
    name: "ÜniCraft",
    ip: serverIp,
    acceptTextures: true
  }]));
}
```

Ayrıca `options.txt` dosyasında kullanıcının tam ekran tercihi her açılışta taranarak kapatılmaktadır:

```javascript
// main.js (Satır 2955 - 2969)
if (/^fullscreen:/m.test(options)) {
  options = options.replace(/^fullscreen:.*$/m, "fullscreen:false");
}
await fsExtra.writeFile(optionsTxtPath, options, "utf8");
```

## 4. Zafiyet ve Hukuki Uyum Özeti

| Kategori | Standart ID | Başlık | Sistemdeki Somut Durum |
|---|---|---|---|
| Yazılım Bütünlüğü | CWE-347 | Improper Verification of Cryptographic Signature | verifySignature = null yapılarak güncelleme imza denetiminin iptal edilmesi |
| Tedarik Zinciri | CWE-494 | Download of Code Without Integrity Check | Genel anahtarın boş bırakılması ve güncellemenin imzasız kabulü |
| Gizlilik İhlali | CWE-359 | Exposure of Private Personal Information | Gizlilik politikasındaki beyanın aksine arka plan süreçlerinin tasklist ile taranması |
| Yerel İzinler | CWE-732 / CWE-459 | Incorrect Permission Assignment / Incomplete Cleanup | icacls ile klasör izinlerinin kısıtlanması ve çökme halinde kilitli kalması |
| Veri Güvenliği | 6698 SK md. 12 | Veri Güvenliğine İlişkin Yükümlülükler | Öğrenci kimlik fotoğraflarının genel geri bildirim kanalında depolanması |

## 5. Topluluk ve Oyuncular İçin Değerlendirme

ÜniCraft Launcher v2.5.6 hakkında öne sürülen hile koruması iddiaları incelendiğinde aşağıdaki teknik sonuçlar ortaya çıkmaktadır:

1. Güncelleme imza denetimi yazılımsal olarak devre dışı bırakılmış; genel anahtar alanı boş bırakılarak istemci dışarıdan gelebilecek müdahalelere açık hale getirilmiştir.
2. Web sitesinde yalnızca dosya hash kontrolü yapıldığı taahhüt edilmesine karşın arka planda çalışan süreçler periyodik olarak taranmaktadır.
3. Özel dizin seçiminde kullanıcının kişisel mod dosyaları onay alınmadan silinmekte ve dosya sistemi izinleri kilitlenmektedir.
4. Donanım yasaklaması mekanizması yerel bir JSON dosyasındaki metin verisine bağlı olup kolaylıkla aşılabilmektedir.
5. Kullanıcının Minecraft sunucu listesi ve ayar dosyaları başlatıcı tarafından tek taraflı olarak ezilmektedir.
6. Öğrenci kimlik kartı fotoğrafları izole bir kimlik altyapısı yerine genel geri bildirim masasında toplanmaktadır.

Bu bulgular ışığında istemcinin vadettiği güvenlik seviyesini karşılamadığı; aksine kullanıcı mahremiyeti, dosya bütünlüğü ve sistem kararlılığı açısından çeşitli riskler barındırdığı görülmektedir.
