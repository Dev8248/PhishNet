# PhishNet

PhishNet helps you judge a suspicious **link, message or QR code before you open it**.
Everything is checked on the device. It never opens, downloads or runs the link you give it.

All application logic and UI are **Java**. The UI is built in code (no XML layouts). The only non-Java
files are the Android manifest and Gradle build files.

## Build and run

Requirements: Android Studio (a recent release), JDK 17 (Android Studio's bundled JDK works), Android SDK Platform 35.

1. Open the `PhishNet` folder in Android Studio and let Gradle sync (it downloads AGP 8.13.0, Gradle 8.13 via the
   wrapper, ZXing 3.5.3 and androidx.activity 1.9.3). If Studio offers to upgrade the Android Gradle plugin, you can accept.
2. Run the `app` configuration on a device or emulator (Android 7.0 / API 24 or newer).
3. Unit tests: `./gradlew :app:testDebugUnitTest` (plain JVM, no device needed).

Assumptions: `minSdk 24`, `targetSdk 35`, `compileSdk 35`, Java 17. There was no existing project, so this is a
minimal new one (package and application id `com.phishnet.app`).

## Dependencies (only two)

| Dependency | Why |
|---|---|
| `com.google.zxing:core:3.5.3` | Offline, pure-Java QR decoding for the one image the user picks. No Google Play services, no network. |
| `androidx.activity:activity:1.9.3` | `ComponentActivity`: the Activity Result API for the **system photo picker** (no storage permission) and the Back-press dispatcher. |

`junit:junit:4.13.2` is used for unit tests only.

## What it does

- **Three ways to start:** paste/type a link; paste/type message text (links are listed and you choose one); pick a
  QR-code image (decoded locally). Text shared to PhishNet from another app only fills the input box.
- **Shows the extracted destination before analysis** for QR codes and for messages, and lets you choose when
  there are several links. A bare link you typed is analysed directly.
- **Never follows a link.** Scanning does not start a browser, WebView or Intent. The only ways a link leaves the app are
  the confirmed "Open link" action (hidden for Risky results and for non-http(s) links) and the donate action (only if configured).
- **Three levels:** Safe (green circle + check), Moderate (yellow triangle + "!"), Risky (red octagon + cross). The written
  label is always shown. One of 8 subtitles per level is drawn at random for every completed scan; it never affects level, score or evidence.
- **Honest scope:** every result says it was checked offline/on-device, lists limits, and shows the evidence behind the score.
- **Privacy:** no account, analytics, ads or tracking; no scan history is saved; the clipboard is read only when you tap
  **Paste**; **no permissions are declared at all** (not even INTERNET); the recents thumbnail is disabled on Android 13+.
- **Menu (three dots):** About, Privacy, Donate to developers (shows "not configured yet" until a real URL is set in `AppConfig.DONATION_URL`).
- Bounded work: input is capped at 20,000 characters, 25 links, 4,096 characters per link; analysis runs on a background
  thread that is cancellable (Back / Cancel).

## Scoring (documented rules)

Score = sum of rule points, capped at 100. **It is not a probability of being attacked.**
`0-19` Safe, `20-49` Moderate, `50-100` Risky. If an important check could not be completed (see "Incomplete" below), a
Safe result is raised to Moderate. The rules are in `analysis/UrlRules.java`, `analysis/TextRules.java`, `analysis/BrandData.java`.

| Area | Rule (id) | Points |
|---|---|---|
| Scheme | plain http (`SCHEME-HTTP`) | +20 |
| | unusual scheme such as ftp (`SCHEME-ODD`) | +25 |
| | javascript:/data:/file:/intent: etc. (`SCHEME-OPAQUE`, `SCHEME-DANGEROUS`) | +60 |
| | no scheme typed, https assumed (`SCHEME-MISSING`) | 0 (info) |
| Syntax | odd slashes, backslashes, several `@`, odd host characters (`SYNTAX-ODD`) | +10 (+15 with odd host characters) |
| | invisible / text-direction / control characters (`SYNTAX-HIDDEN`) | +30 |
| Credentials | user:password in link (`AUTH-CREDENTIALS`) | +35 |
| | deceptive `@` where the part before it looks like a site (`AUTH-AT-DECEPTIVE`) | +55 |
| Host | raw IPv4 / IPv6 (`HOST-IP`, `HOST-IPV6`) | +35 |
| | disguised IP: decimal, hex, octal, short form (`HOST-IP-OBFUSCATED`) | +45 |
| | unusual port (`HOST-PORT`) | +15 (+8 for 8080/8443) |
| | punycode / internationalised name (`HOST-PUNYCODE`) | +25 |
| | mixed alphabets in one label (`HOST-MIXED-SCRIPT`) | +35 |
| | look-alike non-Latin letters (`HOST-CONFUSABLE`) | +30 |
| | 4+ subdomains (`HOST-SUBDOMAINS`) | +15 |
| | host over 50 characters (`HOST-LONG`) / 3+ hyphens (`HOST-HYPHENS`) | +10 each |
| | frequently abused ending such as .top, .xyz (`HOST-TLD`) | +10 |
| | free hosting / tunnel / dynamic DNS (`HOST-FREEHOST`) | +10 |
| | `.com`/`.net`... label inside a subdomain (`HOST-FAKE-TLD`) | +20 |
| | link shortener (`HOST-SHORTENER`) | +20, and scan is Incomplete |
| Brands (about 50 built in) | a real brand domain appears inside the name, e.g. `paypal.com.evil.xyz` (`BRAND-REAL-DOMAIN-INSIDE`) | +55 |
| | misspelling / digit swap / confusable letters of a brand (`BRAND-LOOKALIKE`) | +50 |
| | brand name as a subdomain of an unrelated domain (`BRAND-SUBDOMAIN`) | +50 |
| | brand name inside an unrelated registrable domain (`BRAND-IN-DOMAIN`) | +45 |
| | brand name only in the path/query of an unrelated site (`BRAND-IN-PATH`) | +10 |
| Words | sensitive words in the host, e.g. login, verify (`KEYWORD-HOST`) | +8 each, max 24 |
| | sensitive words in path/query (`KEYWORD-PATH`) | +3 each, max 9 |
| Encoding | percent-encoded host (`ENC-HOST`) | +30 |
| | 3+ percent-encoded letters/digits (`ENC-LETTERS`) / double encoding (`ENC-DOUBLE`) | +15 / +10 |
| | very long link, over 1,000 / over 2,000 characters (`SHAPE-LONG`) | +8 / +15 |
| | a parameter holds another http(s) link (`URL-NESTED`) | +15 |
| Message text (all together capped at 40) | asks for password/OTP/PIN/card/bank details, ignoring "never share..." warnings (`TEXT-SENSITIVE`) | +20, +8 per extra (max 30) |
| | urgency, payment/fee demand, threats (`TEXT-URGENCY`, `TEXT-PAYMENT`, `TEXT-THREAT`) | +6 each phrase (max 12 each) |
| | prize / reward claim (`TEXT-PRIZE`) | +8 |
| Online (optional) | listed as a threat by the configured service (`ONLINE-LISTED`) | +70 |

Keyword and path-brand rules are skipped on well-known first-party domains (for example `accounts.google.com`).

**Incomplete** (a Safe result becomes Moderate; Risky is never lowered): the text was longer than the limit; the link was
longer than 4,096 characters; the link is a shortener (its destination can't be seen without contacting it, which PhishNet never does);
an online check was requested but failed or gave no usable answer.

## Optional online check

The Result screen always shows **Check online**. In this build it is **not available** because no reputation service is
configured, so it explains that and sends nothing. The plumbing exists and is covered by unit tests with a fake service:

1. Implement `online/ReputationService` (it receives only the link, never message text; it must not open or follow the link; no embedded private API keys: use a keyless service or your own proxy).
2. Return it from `AppConfig.reputationService()`.
3. Add `<uses-permission android:name="android.permission.INTERNET" />` to the manifest.

PhishNet then names the service, states what is sent, and asks for confirmation before each request. Online findings are
labelled separately from local ones, and "no match" never lowers the level.

## Known limits (also shown in the app)

- Indicators, not proof. There is no threat-intelligence feed offline, so new, hacked or already-reported sites are invisible to PhishNet.
- It cannot tell whether a device is infected, whether a link relates to your bank account, or who really sent a message.
  It does not scan the device or other apps, and it cannot see redirects or page content.
- The brand list (about 50, with an Indian-bank emphasis), shortener list, abused-TLD list, free-host list and multi-part suffix list are short, static and will go stale. Expect false positives (for example `amazonia.org` looks like an Amazon domain) and false negatives.
- Message wording rules are English keywords only and can be avoided by a scammer or triggered by genuine messages.
- A few fixed subtitles say "message" or "sender" even when the input was only a link or QR code. They are shown verbatim as specified; the evidence list and scope line are what to rely on.
- No live camera scanning (optional in the brief, not implemented). QR images only, through the system photo picker.
- No scan history (optional in the brief, not implemented).
- Default launcher icon (no icon resources were added).

## Layout

```
app/src/main/java/com/phishnet/app/
  MainActivity.java        screen switching, Back, background work, share/paste/QR actions
  AppConfig.java           donation URL (empty) and the reputation service (unavailable)
  analysis/                UrlParser, UrlExtractor, UrlRules, TextRules, BrandData, LookalikeMatcher,
                           RiskAnalyzer, RiskScorer, AnalysisResult, Finding, Subtitles ... (pure Java)
  qr/                      QrDecoder (pure Java, ZXing), QrImageReader (Android bitmap loading)
  online/                  ReputationService, OnlineCheck, UnavailableReputationService
  ui/                      HomeView, PickView, ResultView, StatusView, Dialogs, RiskBadgeView, Ui
app/src/test/java/...      68 JVM unit tests
```
