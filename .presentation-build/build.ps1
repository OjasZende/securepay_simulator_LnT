$ErrorActionPreference = 'Stop'
$taskRoot = 'D:\Lnt_Project\securepay_simulator_LnT'
$buildDir = Join-Path $taskRoot '.presentation-build'
$outputPath = Join-Path $taskRoot 'output\SecurePay_Project_Presentation.pptx'
$previewDir = Join-Path $buildDir 'previews'
New-Item -ItemType Directory -Path $previewDir -Force | Out-Null
function Color([string]$hex) {
    return [Convert]::ToInt32($hex.Substring(0,2),16) + 256*[Convert]::ToInt32($hex.Substring(2,2),16) + 65536*[Convert]::ToInt32($hex.Substring(4,2),16)
}
$navy = Color '102B3F'
$cream = Color 'F5F3ED'
$teal = Color '087F83'
$muted = Color '526674'
$mint = Color '6BD4C3'
$white = Color 'FFFFFF'
$ppt = New-Object -ComObject PowerPoint.Application
$deck = $ppt.Presentations.Add(0)
$deck.PageSetup.SlideWidth = 960
$deck.PageSetup.SlideHeight = 540
$script:dark = $false
$script:issues = @()
function Text($s,[string]$content,[double]$x,[double]$y,[double]$w,[double]$h,[double]$size=20,[bool]$bold=$false,[int]$color=-1) {
    if($color -eq -1) { if($script:dark){$color=$cream}else{$color=$navy} }
    $t=$s.Shapes.AddTextbox(1,$x,$y,$w,$h)
    $t.TextFrame.MarginLeft=0; $t.TextFrame.MarginRight=0
    $t.TextFrame.MarginTop=0; $t.TextFrame.MarginBottom=0
    $t.TextFrame.WordWrap=-1
    $t.TextFrame.AutoSize=0
    $t.TextFrame.TextRange.Text=$content
    $t.TextFrame.TextRange.Font.Name='Arial'
    $t.TextFrame.TextRange.Font.Size=$size
    $t.TextFrame.TextRange.Font.Bold= [int]($bold)*-1
    $t.TextFrame.TextRange.Font.Color.RGB=$color
    $t.TextFrame.TextRange.ParagraphFormat.SpaceAfter=0
    $t.Width=$w
    $t.Height=$h
    return $t
}
function Slide([string]$title,[bool]$dark=$false) {
    $script:dark=$dark
    $s=$deck.Slides.Add($deck.Slides.Count+1,12)
    $s.FollowMasterBackground=0
    $s.Background.Fill.Solid()
    if($dark){$s.Background.Fill.ForeColor.RGB=$navy}else{$s.Background.Fill.ForeColor.RGB=$cream}
    $null=Text $s $title 48 38 864 68 32 $true
    $fc=$muted; if($dark){$fc=$mint}
    $null=Text $s ('{0:D2}' -f $s.SlideIndex) 870 503 40 20 11 $false $fc
    return $s
}
function Notes($s,[string]$body) {
    $s.NotesPage.Shapes.Placeholders.Item(2).TextFrame.TextRange.Text=$body
}
function Pair($s,[string]$a,[string]$b,[double]$y) {
    $ac=$teal; if($script:dark){$ac=$mint}
    $null=Text $s $a 48 $y 228 58 21 $true $ac
    $null=Text $s $b 305 $y 597 72 21
}
function Table($s,$headers,$rows,$widths,[double]$y=140,[double]$height=290,[double]$font=18) {
    $shape=$s.Shapes.AddTable($rows.Count+1,$headers.Count,48,$y,864,$height)
    $tb=$shape.Table
    for($c=1;$c -le $headers.Count;$c++){$tb.Columns.Item($c).Width=$widths[$c-1]}
    $tb.Rows.Item(1).Height=44
    for($r=1;$r -le $rows.Count+1;$r++){
        for($c=1;$c -le $headers.Count;$c++){
            $cell=$tb.Cell($r,$c).Shape
            if($r -eq 1){$value=$headers[$c-1];$bg=$navy;$fg=$white}else{$value=$rows[$r-2][$c-1];$bg=$cream;$fg=$navy}
            $cell.Fill.Solid();$cell.Fill.ForeColor.RGB=$bg
            $cell.TextFrame.MarginLeft=12;$cell.TextFrame.MarginRight=12
            $cell.TextFrame.MarginTop=9;$cell.TextFrame.MarginBottom=7
            $cell.TextFrame.TextRange.Text=[string]$value
            $cell.TextFrame.TextRange.Font.Name='Arial'
            $cell.TextFrame.TextRange.Font.Size=$font
            $cell.TextFrame.TextRange.Font.Color.RGB=$fg
            $cell.TextFrame.TextRange.Font.Bold=0
            if($r -eq 1){$cell.TextFrame.TextRange.Font.Bold=-1}
            foreach($edge in 1..4){$tb.Cell($r,$c).Borders.Item($edge).ForeColor.RGB=(Color 'D8DFDF');$tb.Cell($r,$c).Borders.Item($edge).Weight=0.5}
        }
    }
    return $shape
}

# 01 Cover
$s=Slide 'SecurePay' $true
$s.Shapes.Item(1).Delete()
$null=Text $s 'SecurePay' 48 130 864 78 64 $true
$null=Text $s 'Simulator' 48 210 864 68 50 $false $mint
$null=Text $s 'FinTech payment security with fictional data' 51 322 820 40 25
$null=Text $s 'Problem Statement 03' 51 425 820 26 17 $false $mint
Notes $s 'A local educational payment simulator. The project demonstrates security controls using fictional records. It does not connect to a payment network or establish PCI DSS certification. Source: README.md.'

# 02
$s=Slide 'Project purpose'
$null=Text $s 'Payment data needs protection at every stage' 48 135 850 58 28 $true $teal
Pair $s 'Storage exposure' 'Compare readable customer details with encrypted email stored in SQLite.' 220
Pair $s 'Tampering and access' 'Demonstrate integrity checks, authenticated APIs, and signed receipts.' 310
Pair $s 'Excess collection' 'Reject unnecessary fields and explain the purpose of collected data.' 400
Notes $s 'Project requirements and implemented scope come from README.md and the dashboard in web/index.html. The unprotected examples are educational comparisons, not a second production storage system.'

# 03
$s=Slide 'System architecture'
$null=Text $s 'One local Python application serves the dashboard and APIs' 48 114 864 38 20 $false $muted
$null=Table $s @('Layer','Technology','Responsibility') @(
    ,@('Browser','HTML / CSS / JavaScript','Dashboard and interactive labs')
    ,@('API server','FastAPI + Uvicorn','HTTPS, authentication, validation')
    ,@('Security logic','cryptography + pwdlib','Encryption, PKI, password hashing')
    ,@('Local persistence','SQLite + .secrets/','Records, audit events, key files')
) @(175,265,424) 171 278 18
Notes $s 'Sources: app/main.py serves web/index.html, web/style.css and web/app.js. app/core.py implements SQLite storage, encryption and hashing. app/pki.py creates certificates and signatures. requirements.txt lists FastAPI, uvicorn[standard], cryptography, pwdlib[argon2], pytest and httpx. .secrets is a separate local directory, not an HSM or isolated key service.'

# 04
$s=Slide 'Simulated payment lifecycle' $true
Pair $s '01  Authenticate' 'The API checks the admin username and generated password.' 135
Pair $s '02  Validate' 'Pydantic accepts customer ID, positive amount, and last four digits.' 223
Pair $s '03  Record' 'SQLite stores a demo token and payment. The same transaction adds an audit event.' 311
Pair $s '04  Sign' 'The server signs receipt data with its RSA private key.' 408
Notes $s 'Source: app/main.py::require_admin, Payment and payment; app/core.py::create_payment. POST /api/payments returns 201 for an accepted request. An unknown customer yields 404. Unexpected fields yield 422. A payment token is tok_demo_ plus a random hex value. Every accepted simulated payment receives status approved. No issuer authorization, settlement, token vault or real card processing occurs. amount_cents represents integer minor units and records default to INR.'

# 05
$s=Slide 'Email encryption and tamper detection'
$null=Text $s 'AES-256-GCM' 48 130 864 60 42 $true $teal
Pair $s 'Encryption inputs' 'A 256-bit key, a random 96-bit nonce, and customer-email as authenticated context.' 231
Pair $s 'Stored value' 'Base64 encoding of the nonce, ciphertext, and 128-bit authentication tag.' 321
Pair $s 'Tamper experiment' 'Flipping a bit causes tag verification to fail and blocks decryption.' 411
Notes $s 'Source: app/core.py::encrypt, decrypt and inspect_encryption; tests/test_simulator.py::test_encrypted_storage_and_tampering. Additional Authenticated Data (AAD) is the literal byte string customer-email. KEY is .secrets/data-key.bin, separate from data/securepay.sqlite3. Base64 is an encoding, not the encryption algorithm. The cryptography AESGCM implementation appends a 16-byte authentication tag. Customer names and transaction metadata remain readable to someone with database access. The entire database is not encrypted.'

# 06
$s=Slide 'PKI and secure communication'
$null=Text $s 'HTTPS transport' 48 128 390 36 25 $true $teal
$null=Text $s "A local CA signs an RSA-3072 server certificate for localhost and 127.0.0.1.\n\nThe server uses TLS. API requests over HTTP receive status 426.".Replace('\n',"`r") 48 184 390 235 21
$null=Text $s 'Interactive PKI lab' 510 128 402 36 25 $true $teal
$null=Text $s "1  Verify the certificate signature\n2  Wrap an AES key with RSA-OAEP\n3  Encrypt a message with AES-GCM\n4  Unwrap the key and decrypt\n5  Sign and verify a receipt".Replace('\n',"`r") 510 184 402 245 21
$null=Text $s 'The PKI lab is an application demonstration, separate from the actual TLS handshake.' 48 455 864 36 17 $false $muted
Notes $s 'Sources: app/pki.py::create_certificates, inspect_certificates, simulate_pki_communication and sign_data; app/main.py::require_https_for_api; app/verify_tls.py. Certificate SANs contain localhost and 127.0.0.1. Server validity is 7 days and CA validity is 30 days at generation. The application demonstration uses RSA-OAEP with SHA-256 and ephemeral AES-256-GCM, with RSA PKCS#1 v1.5/SHA-256 signatures. This does not describe the negotiated TLS key exchange. The browser requires trust in the local CA. Certificates, encryption keys and password hashes should never be included in the presentation.'

# 07
$s=Slide 'Access control and input validation'
Pair $s 'Admin access' 'HTTP Basic authentication protects the application APIs over HTTPS.' 135
Pair $s 'Credential storage' 'Setup prints a random one-time password. Only an Argon2id hash is stored.' 225
Pair $s 'Strict request models' 'Customer and payment schemas forbid extra fields. Invalid requests return 422.' 315
Pair $s 'Database writes' 'Bound SQL parameters keep submitted values separate from SQL statements.' 405
Notes $s 'Sources: app/main.py::require_admin, Payment and CustomerCreate; app/core.py::initialize, verify_password and create_payment. Setup uses secrets.token_urlsafe(18). PASSWORD_HASH is .secrets/admin-hash.txt. Username comparison uses secrets.compare_digest. The password checker demonstrates a six-part policy: 12 characters, uppercase, lowercase, digit, special character and exclusion from a short weak-password list. That checker is a lab endpoint, not a registration flow. The current app has a single admin account and does not implement MFA, roles or login throttling.'

# 08
$s=Slide 'Privacy through data minimization'
$null=Table $s @('Data category','Project handling') @(
    ,@('Customer name and email','Keep name for display. Encrypt email at rest.')
    ,@('Payment details','Store customer link, amount, demo token and last four.')
    ,@('Phone, address, date of birth','Omit from customer and payment schemas.')
    ,@('Full PAN, CVV and PIN','Do not accept in customer or payment creation.')
) @(330,534) 140 286 18
$null=Text $s 'The payload inspector explains whether candidate fields are needed, unnecessary, or prohibited by the demo policy.' 48 450 864 55 20 $false $teal
Notes $s 'Sources: app/core.py::FIELDS, EXCESS_FIELDS, analyze_payload_privacy and audit_report; app/main.py::privacy and check_privacy_payload. PAN means Primary Account Number. The inspector classifies PAN as prohibited by this simulator policy; do not generalize that classification into a claim that PCI DSS bans all PAN storage. The arbitrary JSON inspector can receive test fields for classification and does not persist them. Customer and payment creation models reject extra fields. All demonstrations should use fictional values. The app does not actually send email receipts.'

# 09
$s=Slide 'Seeded data: before and after'
$null=Text $s 'Comparison for the two fictional customers created by setup' 48 116 864 32 20 $false $muted
$null=Table $s @('Measure','Illustrative baseline','Protected storage') @(
    ,@('Readable emails in storage','2','0')
    ,@('Encrypted customer emails','0','2 of 2 (100%)')
    ,@('Excess field types','5','0')
    ,@('Payment audit coverage','Not modeled','2 of 2 (100%)')
) @(350,257,257) 172 265 19
$null=Text $s 'The baseline exists only in memory. These are seed-data measurements, not performance benchmarks.' 48 458 864 46 17 $false $muted
Notes $s 'Sources: app/core.py::initialize and audit_report; tests/test_simulator.py::test_access_minimization_and_measurement. Seed data contains 2 customers, 2 transactions and 2 payment_created audit events. The in-memory baseline assembles five excess field types: phone, address, birth_date, pan and cvv. It does not create a plaintext comparison database. Counts can change when a user creates customers or transactions. Audit coverage is the count of audit rows divided by the transaction count, not a cryptographic integrity or event-linkage check.'

# 10
$s=Slide 'Selected PCI DSS principles'
$null=Table $s @('Theme','Implementation evidence') @(
    ,@('Stored data and privacy','Email encryption, minimal schemas, demo payment tokens')
    ,@('Secure transmission','Local CA certificate, HTTPS enforcement, TLS verifier')
    ,@('Application security','Pydantic validation and parameterized SQLite writes')
    ,@('Access and credentials','Admin authentication and salted Argon2id hashes')
    ,@('Activity monitoring','Timestamped payment audit events')
) @(285,579) 132 310 18
$null=Text $s 'The dashboard demonstrates selected principles. Passing its checks does not establish PCI DSS compliance or certification.' 48 463 864 47 17 $false $teal
Notes $s 'Project-specific source: README.md and app/main.py::overview. This slide summarizes the project educational mapping and does not provide a current standards interpretation or independent compliance assessment. The dashboard labels requirements 3.2/3.3, 3.5/3.6, 4.2, 6.2, 7.2/8.3 and 10.2. Those mappings are not independently validated here. The audit_events table has no implemented immutability control, even though some project UI text calls it immutable. A production assessment would need broader technical, operational and organizational evidence.'

# 11
$s=Slide 'Automated verification'
$null=Text $s '6 / 6' 48 125 275 85 60 $true $teal
$null=Text $s 'tests passed' 48 220 275 42 27 $true
$null=Text $s 'Local run on 30 October 2026' 48 284 270 55 18 $false $muted
$null=Table $s @('Test coverage') @(
    ,@('Encryption at rest and ciphertext tampering')
    ,@('Authentication, storage metrics and payments')
    ,@('HTTP rejection and strict customer schemas')
    ,@('PKI delivery, password checks and privacy inspection')
) @(555) 129 302 18
# Shift this single-column evidence table to the right.
$s.Shapes.Item($s.Shapes.Count).Left=357
$s.Shapes.Item($s.Shapes.Count).Width=555
$null=Text $s 'Functional tests use temporary data. They do not establish production readiness.' 48 459 864 42 18 $false $muted
Notes $s 'Source: tests/test_simulator.py. Executed .venv\Scripts\python.exe -m pytest -q on 30 October 2026: 6 passed, 1 deprecation warning, in 5.57 seconds. The warning concerns the Starlette TestClient httpx integration. The pytest demo fixture monkeypatches database and secret paths into tmp_path, creates its own generated credential and certificates, and uses TestClient with https://testserver. The suite contains six test functions, some of which cover several scenarios. These are functional application tests, not browser tests or a network penetration assessment.'

# 12
$s=Slide 'Live demonstration' $true
Pair $s '01  Dashboard' 'Sign in, compare stored ciphertext with the authorized readable view, and add a customer.' 130
Pair $s '02  Security labs' 'Run encryption and PKI delivery once normally, then repeat with tampering enabled.' 223
Pair $s '03  Privacy checks' 'Compare an excessive candidate payload with the minimal payment fields.' 316
Pair $s '04  Payment evidence' 'Create a simulated payment and inspect its token, signature, and audit event.' 409
Notes $s 'Sources: web/index.html, web/app.js and the application API endpoints. Suggested sample email: demo@example.test. Use only fictional inputs. The dashboard login asks for the generated admin password. No secrets are embedded in this deck. A successful encryption run returns VERIFIED. A tampered run returns TAMPER_BLOCKED_INVALID_TAG. PKI simulation returns SECURE_DELIVERY or BLOCKED_TAMPER_DETECTED. The current dashboard decrypts customer emails for an authenticated administrator, so encryption at rest does not hide data from an authorized app session.'

# 13
$s=Slide 'Running the project on Windows'
$null=Text $s 'Initial setup in the project folder' 48 118 864 32 22 $true $teal
$cmd="py -3.13 -m venv .venv`r.\.venv\Scripts\python.exe -m pip install -r requirements.txt`r.\.venv\Scripts\python.exe -m app.setup"
$null=Text $s $cmd 48 164 864 105 17
$null=Text $s 'Start the HTTPS server' 48 280 864 32 22 $true $teal
$cmd=".\.venv\Scripts\python.exe -m uvicorn app.main:app " + [char]96 + "`r  --host 127.0.0.1 --port 8443 " + [char]96 + "`r  --ssl-keyfile .secrets/server-key.pem --ssl-certfile .secrets/server.pem"
$null=Text $s $cmd 48 323 864 94 17
$null=Text $s 'Open https://127.0.0.1:8443 and log in as admin with the password printed by setup.' 48 440 864 58 20 $true
Notes $s 'Source: README.md and app/setup.py. Commands run in PowerShell from the repository root. The start-server command is one command shown across lines for readability: join the three displayed lines with spaces, or use PowerShell backtick line continuations. Direct use of .venv\Scripts\python.exe requires no virtual-environment activation. On an initialized project, skip creating the environment, installing existing dependencies and setup as appropriate. The generated password appears in terminal output after One-time generated password:. It cannot be recovered from the stored hash. app.setup --reset recreates demo records, encryption keys and certificates, so reset is destructive to the current demo data. A local certificate trust warning may appear. Optional checks: .venv\Scripts\python.exe -m app.verify_tls and .venv\Scripts\python.exe -m pytest -v. The current local server certificate lasts 7 days.'

# 14
$s=Slide 'Project scope and next steps'
$null=Text $s 'Implemented learning outcome' 48 125 864 36 25 $true $teal
$null=Text $s 'The simulator makes protection visible through encrypted storage, integrity failures, certificate checks, and minimal request schemas.' 48 180 864 78 25
Pair $s 'Current scope' 'Local fictional payments, one admin account, local key files, and a regular SQLite audit table.' 295
Pair $s 'Future development' 'Role-based access and MFA, managed key rotation, stronger audit integrity, and production deployment testing.' 395
Notes $s 'Sources for current scope: README.md; app/core.py::initialize and create_payment; app/main.py::require_admin; app/pki.py::create_certificates. Future items are proposed extensions, not implemented capabilities or commitments. Other limitations include no real payment gateway, no payment settlement, no production token vault, no external certificate authority and no implemented key rotation. The simulated approved status does not represent authorization by a bank. Existing local key separation does not provide process-level isolation. The project is educational and provides no PCI DSS certification.'

# Save, render all slides, and measure text fit in PowerPoint.
if(Test-Path -LiteralPath $outputPath){throw 'Refusing to overwrite an existing final deck.'}
$deck.SaveAs($outputPath,24)
foreach($s in $deck.Slides){
    $s.Export((Join-Path $previewDir ('slide-{0:D2}.png' -f $s.SlideIndex)),'PNG',1280,720)
    foreach($shape in $s.Shapes){
        if($shape.HasTextFrame -eq -1 -and $shape.TextFrame.HasText -eq -1){
            $range=$shape.TextFrame.TextRange
            if($range.BoundHeight -gt ($shape.Height+2) -or $range.BoundWidth -gt ($shape.Width+2)){
                $script:issues += "Slide $($s.SlideIndex): text overflows shape $($shape.Id)"
            }
        }
    }
}
[pscustomobject]@{SlideCount=$deck.Slides.Count;Output=$outputPath;TextFitIssues=$script:issues} | ConvertTo-Json -Depth 5 | Set-Content (Join-Path $buildDir 'validation.json')
$deck.Close()
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($deck) | Out-Null
[System.Runtime.InteropServices.Marshal]::ReleaseComObject($ppt) | Out-Null
Write-Output "Created $outputPath"
if($script:issues.Count){Write-Output ($script:issues -join "`n")}
