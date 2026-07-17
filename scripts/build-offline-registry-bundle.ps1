[CmdletBinding()]
param(
    [switch]$Help,
    [switch]$DryRun,
    [string]$OutputDirectory,
    [string]$SigningPrivateKey,
    [string]$ImageSbomScanner,
    [string]$ImageSbomScannerSha256,
    [string]$ReleaseSequence,
    [string]$ReleaseId,
    [string]$RegistryBootstrapSource = "docker.io/library/registry:2.8.3@sha256:46faa9a1ae6813194b53921a370f2f4f8c5e1aae228a89bceafef5847a6a3278"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$Usage = @'
Build a signed, content-addressed offline Registry bundle from a clean Git HEAD.

Usage:
  powershell -NoProfile -ExecutionPolicy Bypass -File scripts/build-offline-registry-bundle.ps1 `
    -OutputDirectory C:\release\heyi-kb-2026.07.16.1 `
    -SigningPrivateKey D:\release-keys\heyi-release-rsa.pem `
    -ImageSbomScanner D:\release-tools\syft.exe `
    -ImageSbomScannerSha256 <approved-lowercase-sha256> `
    -ReleaseSequence 202607160001 `
    -ReleaseId 2026.07.16.1

Options:
  -DryRun   Validate the clean-HEAD, tools, key, image and release contracts
            without pulling, building, pushing, signing or publishing artifacts.
  -Help     Print this help and exit.

Security contract:
  * The repository must be clean, including untracked files.
  * Source and release assets are read only from a frozen `git archive HEAD`.
  * The output directory and RSA signing key must be absolute and outside Git.
  * Only linux/amd64 images are accepted. A digest-changing mirror operation fails.
  * A hash-pinned external scanner generates one CycloneDX 1.6 SBOM per final image.
  * The private key is never copied to, or named in, any output artifact or log.
'@

if ($Help) {
    Write-Output $Usage
    exit 0
}

function Fail([string]$Message) {
    throw "offline-bundle-builder: $Message"
}

function Resolve-NativeTool([string]$Name) {
    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($null -eq $command) {
        Fail "required tool is unavailable: $Name"
    }
    $path = [IO.Path]::GetFullPath($command.Source)
    $item = Get-Item -LiteralPath $path -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail "required tool resolves through a reparse point: $Name"
    }
    return $path
}

function Invoke-Captured(
    [string]$Tool,
    [string[]]$Arguments,
    [string]$FailureMessage
) {
    $previousErrorActionPreference = $ErrorActionPreference
    $exitCode = $null
    try {
        # Windows PowerShell 5.1 converts native stderr into ErrorRecord
        # instances. Tools such as Buildx legitimately emit progress there, so
        # their process exit code—not stderr presence—is authoritative.
        $ErrorActionPreference = 'Continue'
        $output = @(& $Tool @Arguments 2>&1)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        $diagnostic = @(
            $output |
                ForEach-Object { $_.ToString().Trim() } |
                Where-Object { $_ } |
                Select-Object -Last 1
        )
        if ($diagnostic.Count -eq 1) {
            $diagnosticText = $diagnostic[0] -replace '[\r\n]+', ' '
            if ($diagnosticText.Length -gt 1024) {
                $diagnosticText = $diagnosticText.Substring(0, 1024) + '...'
            }
            Fail "$FailureMessage; native diagnostic: $diagnosticText"
        }
        Fail $FailureMessage
    }
    return @($output | ForEach-Object { $_.ToString() })
}

function Invoke-Quiet(
    [string]$Tool,
    [string[]]$Arguments,
    [string]$FailureMessage
) {
    $previousErrorActionPreference = $ErrorActionPreference
    $exitCode = $null
    try {
        $ErrorActionPreference = 'Continue'
        & $Tool @Arguments 1>$null 2>$null
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($exitCode -ne 0) {
        Fail $FailureMessage
    }
}

function Read-DockerLabels(
    [string]$Docker,
    [ValidateSet('container', 'network')]
    [string]$ResourceKind,
    [string]$ResourceId
) {
    $arguments = if ($ResourceKind -eq 'container') {
        @('inspect', '--format', '{{json .Config.Labels}}', $ResourceId)
    }
    else {
        @('network', 'inspect', '--format', '{{json .Labels}}', $ResourceId)
    }
    try {
        $output = @(& $Docker @arguments 2>$null)
        $exitCode = $LASTEXITCODE
    }
    catch {
        return [PSCustomObject]@{ Succeeded = $false; Labels = $null }
    }
    if ($exitCode -ne 0 -or $output.Count -ne 1) {
        return [PSCustomObject]@{ Succeeded = $false; Labels = $null }
    }
    try {
        $labels = $output[0].ToString() | ConvertFrom-Json -ErrorAction Stop
    }
    catch {
        return [PSCustomObject]@{ Succeeded = $false; Labels = $null }
    }
    if ($null -eq $labels) {
        return [PSCustomObject]@{ Succeeded = $false; Labels = $null }
    }
    return [PSCustomObject]@{ Succeeded = $true; Labels = $labels }
}

function Resolve-LoopbackPublishedPort(
    [string]$Docker,
    [string]$ContainerId
) {
    for ($attempt = 0; $attempt -lt 20; $attempt++) {
        try {
            $output = @(& $Docker inspect --format `
                '{{json .NetworkSettings.Ports}}' $ContainerId 2>$null)
            $exitCode = $LASTEXITCODE
            if ($exitCode -eq 0 -and $output.Count -eq 1) {
                $ports = $output[0].ToString() | ConvertFrom-Json -ErrorAction Stop
                $properties = @($ports.PSObject.Properties.Name)
                $bindings = @($ports.'5000/tcp')
                if ($properties.Count -eq 1 -and $properties[0] -eq '5000/tcp' -and
                    $bindings.Count -eq 1 -and $bindings[0].HostIp -eq '127.0.0.1' -and
                    $bindings[0].HostPort -match '^[1-9][0-9]{0,4}$' -and
                    [int]$bindings[0].HostPort -le 65535) {
                    return "127.0.0.1:$($bindings[0].HostPort)"
                }
            }
        }
        catch {
            # Docker 29 may publish the random host port asynchronously.
        }
        Start-Sleep -Milliseconds 100
    }
    return $null
}

function Test-IsWithin([string]$Candidate, [string]$Parent) {
    $candidateFull = [IO.Path]::GetFullPath($Candidate).TrimEnd('\', '/')
    $parentFull = [IO.Path]::GetFullPath($Parent).TrimEnd('\', '/')
    if ($candidateFull.Equals($parentFull, [StringComparison]::OrdinalIgnoreCase)) {
        return $true
    }
    $prefix = $parentFull + [IO.Path]::DirectorySeparatorChar
    return $candidateFull.StartsWith($prefix, [StringComparison]::OrdinalIgnoreCase)
}

function Assert-CleanRepository([string]$Git, [string]$Repository) {
    $status = @(Invoke-Captured $Git @(
        '-C', $Repository, 'status', '--porcelain=v1', '--untracked-files=all'
    ) 'cannot inspect repository cleanliness')
    if ($status.Count -ne 0) {
        Fail 'repository is dirty; commit or remove every tracked and untracked change'
    }
}

function Write-AsciiFile([string]$Path, [string[]]$Lines) {
    $parent = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) {
        [void][IO.Directory]::CreateDirectory($parent)
    }
    $temporary = "$Path.tmp.$([Guid]::NewGuid().ToString('N'))"
    $content = ($Lines -join "`n") + "`n"
    [IO.File]::WriteAllText($temporary, $content, [Text.Encoding]::ASCII)
    [IO.File]::Move($temporary, $Path)
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
}

function Assert-RegularTree([string]$Root) {
    foreach ($item in Get-ChildItem -LiteralPath $Root -Force -Recurse) {
        if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
            Fail 'staging tree contains a reparse point or symbolic link'
        }
        if (-not ($item.PSIsContainer -or ($item -is [IO.FileInfo]))) {
            Fail 'staging tree contains an unsupported filesystem object'
        }
    }
}

function Get-ReleaseContractAssets([string]$CommonScript) {
    $text = [IO.File]::ReadAllText($CommonScript)
    $pattern = "(?ms)^offline_contract_files\(\) \{\r?\n\s*cat <<'EOF'\r?\n(?<body>.*?)\r?\nEOF\r?\n\}"
    $match = [Text.RegularExpressions.Regex]::Match($text, $pattern)
    if (-not $match.Success) {
        Fail 'cannot parse the canonical offline release contract'
    }
    $entries = @($match.Groups['body'].Value -split "`r?`n" | Where-Object { $_ -ne '' })
    $expectedInputs = @('runtime.env', 'release.env', 'release.env.images')
    foreach ($required in $expectedInputs) {
        if (@($entries | Where-Object { $_ -eq $required }).Count -ne 1) {
            Fail 'canonical offline contract has an invalid environment boundary'
        }
    }
    $assets = @($entries | Where-Object { $_.StartsWith('release/', [StringComparison]::Ordinal) })
    if ($assets.Count -eq 0 -or $assets.Count -ne ($entries.Count - 3)) {
        Fail 'canonical offline contract contains an unsupported path'
    }
    if (@($assets | Sort-Object -Unique).Count -ne $assets.Count) {
        Fail 'canonical offline contract contains duplicate assets'
    }
    foreach ($asset in $assets) {
        if ($asset -notmatch '^release/[A-Za-z0-9._/-]+$' -or
            $asset.Contains('//') -or $asset.Contains('/../') -or $asset.EndsWith('/..')) {
            Fail 'canonical offline contract contains an unsafe asset path'
        }
    }
    return $assets
}

function Get-ExpectedSchemaHead([string]$SchemaVersionFile) {
    $text = [IO.File]::ReadAllText($SchemaVersionFile)
    $matches = [Text.RegularExpressions.Regex]::Matches(
        $text,
        'EXPECTED_ALEMBIC_HEADS\s*=\s*frozenset\(\{"([A-Za-z0-9_]+)"\}\)'
    )
    if ($matches.Count -ne 1) {
        Fail 'application must declare exactly one expected Alembic head'
    }
    $head = $matches[0].Groups[1].Value
    if ($head -notmatch '^\d{8}_\d{4}$') {
        Fail 'application Alembic head has an unsupported format'
    }
    return $head
}

function Assert-DockerfilePinned([string]$Dockerfile) {
    $arguments = @{}
    $stages = @{}
    foreach ($rawLine in [IO.File]::ReadAllLines($Dockerfile)) {
        $line = $rawLine.Trim()
        if ($line -match '^ARG\s+([A-Za-z_][A-Za-z0-9_]*)=(\S+)$') {
            $arguments[$matches[1]] = $matches[2]
            continue
        }
        if ($line -notmatch '^FROM\s+(?:--platform=\S+\s+)?(\S+)(?:\s+AS\s+(\S+))?$') {
            continue
        }
        $image = $matches[1]
        $stageName = $matches[2]
        if ($image -match '^\$\{([A-Za-z_][A-Za-z0-9_]*)\}$') {
            if (-not $arguments.ContainsKey($matches[1])) {
                Fail 'Dockerfile uses an undeclared image argument'
            }
            $image = $arguments[$matches[1]]
        }
        if (-not $stages.ContainsKey($image) -and
            $image -notmatch '^.+@sha256:[0-9a-f]{64}$') {
            Fail 'Dockerfile contains a mutable base image'
        }
        if ($stageName) {
            $stages[$stageName] = $true
        }
    }
}

function Assert-DockerIgnoreSecretBoundary([string]$DockerIgnore) {
    if (-not (Test-Path -LiteralPath $DockerIgnore -PathType Leaf)) {
        Fail 'Docker build context must define a secret-exclusion boundary'
    }
    $rules = @(
        [IO.File]::ReadAllLines($DockerIgnore) |
            ForEach-Object { $_.Trim() } |
            Where-Object { $_ -and -not $_.StartsWith('#', [StringComparison]::Ordinal) }
    )
    foreach ($required in @('.env', '.env.*')) {
        if ($rules -notcontains $required) {
            Fail 'Docker build context does not exclude local environment secrets'
        }
    }
}

function Get-PinnedComposeImages([string]$ComposeFile) {
    $images = New-Object 'System.Collections.Generic.List[string]'
    foreach ($rawLine in [IO.File]::ReadAllLines($ComposeFile)) {
        if ($rawLine -notmatch '^\s+image:\s+(\S+)\s*$') {
            continue
        }
        $image = $matches[1]
        if ($image.StartsWith('${', [StringComparison]::Ordinal)) {
            if ($image -notmatch '^\$\{KB_(API|MIGRATION|WEB)_IMAGE:\?required\}$') {
                Fail 'Compose contains an unknown dynamic image reference'
            }
            continue
        }
        if ($image -notmatch '^127\.0\.0\.1:5000/heyi-mirror/[A-Za-z0-9._/:@-]+@sha256:[0-9a-f]{64}$') {
            Fail 'Compose contains a mutable or non-loopback fixed image'
        }
        [void]$images.Add($image)
    }
    $unique = @($images | Sort-Object -Unique)
    if ($unique.Count -lt 1) {
        Fail 'Compose fixed-image inventory is empty'
    }
    return $unique
}

function Get-ReferenceWithoutDigest([string]$Reference) {
    $separator = $Reference.LastIndexOf('@sha256:', [StringComparison]::Ordinal)
    if ($separator -le 0 -or ($Reference.Length - $separator) -ne 72) {
        Fail 'image reference does not contain one terminal SHA-256 digest'
    }
    return $Reference.Substring(0, $separator)
}

function Get-DigestFromReference([string]$Reference) {
    $separator = $Reference.LastIndexOf('@sha256:', [StringComparison]::Ordinal)
    if ($separator -le 0 -or ($Reference.Length - $separator) -ne 72) {
        Fail 'image reference does not contain one terminal SHA-256 digest'
    }
    return $Reference.Substring($separator + 1)
}

function Read-BoundedResponseBytes(
    [IO.Stream]$Stream,
    [long]$MaximumBytes,
    [string]$BoundaryMessage
) {
    if ($null -eq $Stream -or $MaximumBytes -le 0 -or
        $MaximumBytes -ge [int]::MaxValue -or -not $BoundaryMessage) {
        Fail 'bounded response reader received an invalid contract'
    }
    $memory = New-Object IO.MemoryStream
    $buffer = New-Object byte[] 65536
    $maximumPlusOne = $MaximumBytes + 1
    try {
        while ($memory.Length -lt $maximumPlusOne) {
            $remaining = $maximumPlusOne - $memory.Length
            $requested = [int][Math]::Min([long]$buffer.Length, $remaining)
            $read = $Stream.Read($buffer, 0, $requested)
            if ($read -eq 0) {
                break
            }
            if ($read -lt 0 -or $read -gt $requested) {
                Fail 'response stream returned an invalid byte count'
            }
            $memory.Write($buffer, 0, $read)
        }
        if ($memory.Length -gt $MaximumBytes) {
            Fail $BoundaryMessage
        }
        if ($memory.Length -eq 0) {
            Fail 'temporary Registry returned an empty response body'
        }
        $bytes = $memory.ToArray()
    }
    finally {
        $memory.Dispose()
    }
    # Prevent PowerShell from unrolling byte[] into one pipeline object per byte.
    return ,$bytes
}

function Invoke-StrictRegistryJsonInspection(
    [string]$Python,
    [string]$Workspace,
    [byte[]]$JsonBytes,
    [ValidateSet('manifest', 'config')]
    [string]$Mode
) {
    if (-not $Python -or -not $Workspace -or $null -eq $JsonBytes -or
        $JsonBytes.Length -eq 0) {
        Fail 'strict Registry JSON inspector received an invalid contract'
    }
    $inspectionId = [Guid]::NewGuid().ToString('N')
    $programPath = Join-Path $Workspace "registry-json-$inspectionId.py"
    $documentPath = Join-Path $Workspace "registry-json-$inspectionId.bin"
    if ((Test-Path -LiteralPath $programPath) -or
        (Test-Path -LiteralPath $documentPath)) {
        Fail 'strict Registry JSON inspection path already exists'
    }
    $program = @'
import json
import pathlib
import re
import sys

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
MANIFEST_TYPES = {
    "application/vnd.docker.distribution.manifest.v2+json",
    "application/vnd.oci.image.manifest.v1+json",
}
CONFIG_TYPES = {
    "application/vnd.docker.container.image.v1+json",
    "application/vnd.oci.image.config.v1+json",
}
MAX_MANIFEST_BYTES = 4 * 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024


def fail(message):
    raise SystemExit(f"registry-json-inspector: {message}")


def reject_constant(value):
    fail(f"JSON contains a non-finite number: {value}")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("JSON contains a duplicate object key")
        value[key] = item
    return value


def load_object(path, maximum, label):
    candidate = pathlib.Path(path)
    if not candidate.is_file() or candidate.is_symlink():
        fail(f"{label} input is not a regular file")
    with candidate.open("rb") as stream:
        data = stream.read(maximum + 1)
    if not data or len(data) > maximum:
        fail(f"{label} input size is outside the approved boundary")
    try:
        text = data.decode("utf-8", errors="strict")
        value = json.loads(
            text,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        fail(f"{label} is not valid UTF-8 JSON")
    if type(value) is not dict:
        fail(f"{label} must be a JSON object")
    return value


def inspect_manifest(path):
    manifest = load_object(path, MAX_MANIFEST_BYTES, "manifest")
    if type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2:
        fail("manifest schemaVersion must be the integer 2")
    media_type = manifest.get("mediaType")
    if type(media_type) is not str or media_type not in MANIFEST_TYPES:
        fail("manifest is not an approved single-image media type")
    descriptor = manifest.get("config")
    if type(descriptor) is not dict:
        fail("manifest config descriptor must be an object")
    config_media_type = descriptor.get("mediaType")
    digest = descriptor.get("digest")
    size = descriptor.get("size")
    if (
        type(config_media_type) is not str
        or config_media_type not in CONFIG_TYPES
        or type(digest) is not str
        or DIGEST.fullmatch(digest) is None
        or type(size) is not int
        or not 0 < size <= MAX_CONFIG_BYTES
    ):
        fail("manifest config descriptor is invalid")
    layers = manifest.get("layers")
    if type(layers) is not list or not layers:
        fail("manifest layer descriptor set must be a non-empty array")
    for layer in layers:
        if type(layer) is not dict:
            fail("manifest layer descriptor must be an object")
        layer_digest = layer.get("digest")
        layer_size = layer.get("size")
        if (
            type(layer_digest) is not str
            or DIGEST.fullmatch(layer_digest) is None
            or type(layer_size) is not int
            or layer_size <= 0
        ):
            fail("manifest contains an invalid layer descriptor")
    print(f"{digest}\t{size}")


def inspect_config(path):
    config = load_object(path, MAX_CONFIG_BYTES, "config blob")
    if type(config.get("os")) is not str or config["os"] != "linux":
        fail("config blob operating system must be linux")
    if type(config.get("architecture")) is not str or config["architecture"] != "amd64":
        fail("config blob architecture must be amd64")
    print("PASS")


if len(sys.argv) != 3 or sys.argv[1] not in {"manifest", "config"}:
    fail("usage: registry-json-inspector.py <manifest|config> <document>")
if sys.argv[1] == "manifest":
    inspect_manifest(sys.argv[2])
else:
    inspect_config(sys.argv[2])
'@
    try {
        Write-AsciiFile $programPath @($program -split '\r?\n')
        [IO.File]::WriteAllBytes($documentPath, $JsonBytes)
        return @(Invoke-Captured $Python @('-I', $programPath, $Mode, $documentPath) `
            'strict Registry JSON inspection failed')
    }
    finally {
        foreach ($temporaryInspectionFile in @($documentPath, $programPath)) {
            if (Test-Path -LiteralPath $temporaryInspectionFile) {
                Remove-Item -LiteralPath $temporaryInspectionFile -Force
            }
        }
    }
}

function Get-RegistryManifestConfigId(
    [string]$Python,
    [string]$Workspace,
    [string]$TemporaryTaggedImage,
    [string]$ExpectedManifestDigest
) {
    $match = [Text.RegularExpressions.Regex]::Match(
        $TemporaryTaggedImage,
        '^(?<endpoint>127\.0\.0\.1:[1-9][0-9]{0,4})/(?<repository>[a-z0-9][a-z0-9._/-]*):(?<tag>[A-Za-z0-9_][A-Za-z0-9_.-]{0,127})$'
    )
    if (-not $match.Success -or
        $ExpectedManifestDigest -notmatch '^sha256:[0-9a-f]{64}$') {
        Fail 'cannot derive a safe temporary Registry manifest URL'
    }
    $endpoint = $match.Groups['endpoint'].Value
    $repository = $match.Groups['repository'].Value
    if ($repository.Contains('//') -or $repository.Contains('/../') -or
        $repository.EndsWith('/..')) {
        Fail 'temporary Registry repository path is unsafe'
    }
    $uri = "http://$endpoint/v2/$repository/manifests/$ExpectedManifestDigest"
    $request = [Net.HttpWebRequest]::Create($uri)
    $request.Method = 'GET'
    $request.Proxy = $null
    $request.Timeout = 10000
    $request.ReadWriteTimeout = 10000
    $request.Accept = (
        'application/vnd.docker.distribution.manifest.v2+json, ' +
        'application/vnd.oci.image.manifest.v1+json'
    )
    $response = $null
    try {
        $response = [Net.HttpWebResponse]$request.GetResponse()
        if ([int]$response.StatusCode -ne 200) {
            Fail 'temporary Registry returned a non-success manifest response'
        }
        if ($response.Headers['Docker-Content-Digest'] -ne $ExpectedManifestDigest) {
            Fail 'temporary Registry manifest response changed its content digest'
        }
        if ($response.ContentLength -eq 0 -or $response.ContentLength -gt 4194304) {
            Fail 'temporary Registry manifest size is outside the approved boundary'
        }
        $stream = $response.GetResponseStream()
        try {
            $bytes = Read-BoundedResponseBytes $stream 4194304 `
                'temporary Registry manifest size is outside the approved boundary'
        }
        finally {
            if ($null -ne $stream) {
                $stream.Dispose()
            }
        }
    }
    catch {
        if ($_.Exception.Message -like 'offline-bundle-builder:*') {
            throw
        }
        Fail 'cannot read the exact manifest from the temporary Registry'
    }
    finally {
        if ($null -ne $response) {
            $response.Dispose()
        }
    }

    $sha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $bodyDigest = 'sha256:' + (
            [BitConverter]::ToString($sha256.ComputeHash($bytes)).Replace('-', '').ToLowerInvariant()
        )
    }
    finally {
        $sha256.Dispose()
    }
    if ($bodyDigest -ne $ExpectedManifestDigest) {
        Fail 'temporary Registry manifest bytes do not match their content address'
    }
    $manifestInspection = @(Invoke-StrictRegistryJsonInspection `
        $Python $Workspace $bytes 'manifest')
    if ($manifestInspection.Count -ne 1) {
        Fail 'temporary Registry manifest inspection returned a malformed result'
    }
    $manifestResult = [Text.RegularExpressions.Regex]::Match(
        $manifestInspection[0],
        '^(sha256:[0-9a-f]{64})\t([1-9][0-9]{0,7})$'
    )
    if (-not $manifestResult.Success) {
        Fail 'temporary Registry manifest inspection returned an invalid config descriptor'
    }
    $configId = $manifestResult.Groups[1].Value
    $configSize = [long]$manifestResult.Groups[2].Value
    if ($configSize -le 0 -or $configSize -gt 16777216) {
        Fail 'temporary Registry image config exceeds the approved size'
    }
    $configRequest = [Net.HttpWebRequest]::Create(
        "http://$endpoint/v2/$repository/blobs/$configId"
    )
    $configRequest.Method = 'GET'
    $configRequest.Proxy = $null
    $configRequest.Timeout = 10000
    $configRequest.ReadWriteTimeout = 10000
    $configRequest.Accept = 'application/octet-stream'
    $configResponse = $null
    try {
        $configResponse = [Net.HttpWebResponse]$configRequest.GetResponse()
        if ([int]$configResponse.StatusCode -ne 200 -or
            ($configResponse.ContentLength -ge 0 -and
                $configResponse.ContentLength -ne $configSize)) {
            Fail 'temporary Registry config blob response is invalid'
        }
        $configStream = $configResponse.GetResponseStream()
        try {
            $configBytes = Read-BoundedResponseBytes $configStream $configSize `
                'temporary Registry config blob exceeds its descriptor size'
        }
        finally {
            if ($null -ne $configStream) {
                $configStream.Dispose()
            }
        }
    }
    catch {
        if ($_.Exception.Message -like 'offline-bundle-builder:*') {
            throw
        }
        Fail 'cannot read the image config from the temporary Registry'
    }
    finally {
        if ($null -ne $configResponse) {
            $configResponse.Dispose()
        }
    }
    if ($configBytes.Length -ne $configSize) {
        Fail 'temporary Registry config blob size differs from its descriptor'
    }
    $configSha256 = [Security.Cryptography.SHA256]::Create()
    try {
        $observedConfigId = 'sha256:' + (
            [BitConverter]::ToString(
                $configSha256.ComputeHash($configBytes)
            ).Replace('-', '').ToLowerInvariant()
        )
    }
    finally {
        $configSha256.Dispose()
    }
    if ($observedConfigId -ne $configId) {
        Fail 'temporary Registry config bytes do not match their content address'
    }
    $configInspection = @(Invoke-StrictRegistryJsonInspection `
        $Python $Workspace $configBytes 'config')
    if ($configInspection.Count -ne 1 -or $configInspection[0] -ne 'PASS') {
        Fail 'temporary Registry image config platform is not linux/amd64'
    }
    return $configId
}

function Get-DockerArchiveSingleConfigId(
    [string]$Python,
    [string]$Archive,
    [string]$Workspace,
    [string]$ExpectedTag
) {
    $programPath = Join-Path $Workspace 'inspect-bootstrap-config.py'
    if (Test-Path -LiteralPath $programPath) {
        Fail 'bootstrap config inspection program already exists'
    }
    $program = @'
import hashlib
import json
import pathlib
import re
import sys
import tarfile

CONFIG_PATH = re.compile(
    r"^(?:(?P<legacy>[0-9a-f]{64})\.json|blobs/sha256/(?P<oci>[0-9a-f]{64}))$"
)
BOOTSTRAP_TAG = re.compile(
    r"^[a-z0-9][a-z0-9._/-]*:[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$"
)
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_CONFIG_BYTES = 16 * 1024 * 1024


def fail(message):
    raise SystemExit(f"bootstrap-config: {message}")


def reject_constant(value):
    fail(f"JSON contains a non-finite number: {value}")


def unique_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            fail("JSON contains a duplicate object key")
        value[key] = item
    return value


if len(sys.argv) != 3 or BOOTSTRAP_TAG.fullmatch(sys.argv[2]) is None:
    fail("usage: inspect-bootstrap-config.py <archive> <expected-tag>")
archive_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
expected_tag = sys.argv[2]
with tarfile.open(archive_path, "r:*") as archive:
    members = {}
    for member in archive.getmembers():
        if member.name in members:
            fail("Docker archive contains duplicate paths")
        members[member.name] = member
    manifest_member = members.get("manifest.json")
    if (
        manifest_member is None
        or not manifest_member.isfile()
        or manifest_member.issym()
        or manifest_member.islnk()
        or not 0 < manifest_member.size <= MAX_MANIFEST_BYTES
    ):
        fail("Docker archive manifest is missing or unsafe")
    manifest_stream = archive.extractfile(manifest_member)
    if manifest_stream is None:
        fail("Docker archive manifest cannot be read")
    try:
        manifest_bytes = manifest_stream.read(MAX_MANIFEST_BYTES + 1)
        if len(manifest_bytes) != manifest_member.size:
            fail("Docker archive manifest size differs from its header")
        manifest = json.loads(
            manifest_bytes,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        fail("Docker archive manifest is invalid JSON")
    if not isinstance(manifest, list) or len(manifest) != 1:
        fail("Docker archive must contain exactly one bootstrap image")
    entry = manifest[0]
    if not isinstance(entry, dict):
        fail("Docker archive manifest entry must be an object")
    repo_tags = entry.get("RepoTags")
    if repo_tags != [expected_tag]:
        fail("Docker archive RepoTags must contain exactly the signed bootstrap tag")
    config_path = entry.get("Config")
    match = CONFIG_PATH.fullmatch(config_path or "")
    if match is None:
        fail("Docker archive config path is not content addressed")
    config_digest = match.group("legacy") or match.group("oci")
    config_member = members.get(config_path)
    if (
        config_member is None
        or not config_member.isfile()
        or config_member.issym()
        or config_member.islnk()
        or not 0 < config_member.size <= MAX_CONFIG_BYTES
    ):
        fail("Docker archive config is missing or unsafe")
    config_stream = archive.extractfile(config_member)
    if config_stream is None:
        fail("Docker archive config cannot be read")
    config_bytes = config_stream.read(MAX_CONFIG_BYTES + 1)
    if len(config_bytes) != config_member.size:
        fail("Docker archive config size differs from its header")
    if hashlib.sha256(config_bytes).hexdigest() != config_digest:
        fail("Docker archive config bytes do not match their content address")
    try:
        config = json.loads(
            config_bytes,
            object_pairs_hook=unique_object,
            parse_constant=reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, RecursionError):
        fail("Docker archive config is invalid JSON")
    if not isinstance(config, dict):
        fail("Docker archive config must be an object")
    if config.get("os") != "linux" or config.get("architecture") != "amd64":
        fail("Docker archive config platform must be linux/amd64")
print(f"sha256:{config_digest}")
'@
    Write-AsciiFile $programPath @($program -split '\r?\n')
    try {
        $output = @(Invoke-Captured $Python @(
            '-I', $programPath, $Archive, $ExpectedTag
        ) `
            'cannot determine the bootstrap image config digest')
    }
    finally {
        if (Test-Path -LiteralPath $programPath) {
            Remove-Item -LiteralPath $programPath -Force
        }
    }
    if ($output.Count -ne 1 -or $output[0] -notmatch '^sha256:[0-9a-f]{64}$') {
        Fail 'bootstrap image config inspection returned an invalid identity'
    }
    return $output[0]
}

function Get-DeduplicatedUnpackedCapacity(
    [string]$Docker,
    [string]$Python,
    [object[]]$ImageRecords,
    [string]$Workspace
) {
    $digestToConfigId = @{}
    foreach ($record in $ImageRecords) {
        $manifestMatch = [Text.RegularExpressions.Regex]::Match(
            $record.Reference,
            '@(sha256:[0-9a-f]{64})$'
        )
        if (-not $manifestMatch.Success -or
            $record.ConfigId -notmatch '^sha256:[0-9a-f]{64}$') {
            Fail 'capacity measurement received an invalid final image identity'
        }
        $manifestDigest = $manifestMatch.Groups[1].Value
        if ($digestToConfigId.ContainsKey($manifestDigest) -and
            $digestToConfigId[$manifestDigest] -ne $record.ConfigId) {
            Fail 'one final manifest digest resolves to multiple image configs'
        }
        $digestToConfigId[$manifestDigest] = $record.ConfigId
    }
    if ($digestToConfigId.Count -eq 0) {
        Fail 'capacity measurement requires at least one final image digest'
    }

    # docker image save emits one archive containing the final, de-duplicated
    # config set. Its manifest preserves shared layer paths, so parsing every
    # unique path once measures uncompressed layers instead of multiplying the
    # compressed Registry directory by an empirical factor.
    $configIds = @($digestToConfigId.Values | Sort-Object -Unique)
    $localImageIds = @(
        $ImageRecords |
            Select-Object -ExpandProperty LocalScanId |
            Sort-Object -Unique
    )
    if ($localImageIds.Count -ne $configIds.Count -or
        @($localImageIds | Where-Object { $_ -notmatch '^sha256:[0-9a-f]{64}$' }).Count -ne 0) {
        Fail 'capacity measurement received an invalid local image identity set'
    }
    $measurementArchive = Join-Path $Workspace 'unpacked-image-capacity.tar'
    if (Test-Path -LiteralPath $measurementArchive) {
        Fail 'capacity measurement archive already exists'
    }
    $saveArguments = @('image', 'save', '--output', $measurementArchive) + $localImageIds

    $program = @'
import gzip
import hashlib
import io
import json
import pathlib
import posixpath
import re
import sys
import tarfile

DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
CONFIG_PATH = re.compile(
    r"^(?:(?P<legacy>[0-9a-f]{64})\.json|blobs/sha256/(?P<oci>[0-9a-f]{64}))$"
)
BLOB_PATH = re.compile(r"^blobs/sha256/(?P<digest>[0-9a-f]{64})$")


def fail(message):
    raise SystemExit(f"unpacked-capacity: {message}")


def archive_member(archive, members, name):
    member = members.get(name)
    if member is None or not member.isfile() or member.issym() or member.islnk():
        fail("Docker archive contains a missing or unsafe regular file")
    stream = archive.extractfile(member)
    if stream is None:
        fail("Docker archive member cannot be read")
    return stream


def sha256_stream(stream):
    digest = hashlib.sha256()
    while chunk := stream.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def open_uncompressed_layer(stream):
    header = stream.peek(6)[:6]
    if header.startswith(b"\x1f\x8b"):
        return gzip.GzipFile(fileobj=stream, mode="rb")
    if (
        header.startswith(b"BZh")
        or header.startswith(b"\xfd7zXZ\x00")
        or header.startswith(b"\x28\xb5\x2f\xfd")
    ):
        fail("Docker archive uses an unsupported layer compression")
    return stream


class DigestingReader(io.RawIOBase):
    def __init__(self, stream, digest):
        super().__init__()
        self.stream = stream
        self.digest = digest

    def readable(self):
        return True

    def readinto(self, buffer):
        chunk = self.stream.read(len(buffer))
        if not chunk:
            return 0
        buffer[: len(chunk)] = chunk
        self.digest.update(chunk)
        return len(chunk)


def safe_relative_path(value, *, allow_root=False):
    if not isinstance(value, str) or not value or "\\" in value or value.startswith("/"):
        fail("archive contains an unsafe path")
    normalized = posixpath.normpath(value)
    if normalized in {"", "."}:
        if allow_root:
            return "."
        fail("archive contains an empty path")
    if normalized == ".." or normalized.startswith("../"):
        fail("archive path escapes its root")
    parts = pathlib.PurePosixPath(normalized).parts
    if any(part in {"", ".", ".."} for part in parts):
        fail("archive contains a non-canonical path")
    return pathlib.PurePosixPath(*parts).as_posix()


archive_path = pathlib.Path(sys.argv[1]).resolve(strict=True)
expected_configs = set(sys.argv[2:])
if not expected_configs or len(expected_configs) != len(sys.argv[2:]):
    fail("expected image config set is empty or duplicated")
if any(DIGEST.fullmatch(value) is None for value in expected_configs):
    fail("expected image config identity is invalid")

with tarfile.open(archive_path, "r:*") as outer:
    members = {}
    for member in outer.getmembers():
        if member.name in members:
            fail("Docker archive contains duplicate member paths")
        members[member.name] = member

    with archive_member(outer, members, "manifest.json") as stream:
        manifest = json.load(stream)
    if not isinstance(manifest, list) or not manifest:
        fail("Docker archive manifest is empty or malformed")

    observed_configs = set()
    layer_diff_ids = {}
    for image in manifest:
        if not isinstance(image, dict):
            fail("Docker archive manifest entry is malformed")
        config_path = safe_relative_path(image.get("Config"))
        config_match = CONFIG_PATH.fullmatch(config_path)
        if config_match is None:
            fail("Docker archive config path is not content addressed")
        config_digest = config_match.group("legacy") or config_match.group("oci")
        config_id = f"sha256:{config_digest}"
        if config_id in observed_configs:
            fail("Docker archive contains a duplicate image config")
        observed_configs.add(config_id)
        with archive_member(outer, members, config_path) as stream:
            config_bytes = stream.read()
        if hashlib.sha256(config_bytes).hexdigest() != config_digest:
            fail("Docker archive config bytes do not match their content address")
        try:
            config = json.loads(config_bytes)
        except (UnicodeDecodeError, json.JSONDecodeError):
            fail("Docker archive image config is invalid JSON")
        rootfs = config.get("rootfs") if isinstance(config, dict) else None
        diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
        layers = image.get("Layers")
        if (
            not isinstance(diff_ids, list)
            or not isinstance(layers, list)
            or not diff_ids
            or len(diff_ids) != len(layers)
        ):
            fail("Docker archive layer contract is incomplete")
        for layer_name_raw, diff_id in zip(layers, diff_ids, strict=True):
            layer_name = safe_relative_path(layer_name_raw)
            if DIGEST.fullmatch(diff_id) is None:
                fail("Docker archive contains an invalid layer DiffID")
            previous = layer_diff_ids.setdefault(layer_name, diff_id)
            if previous != diff_id:
                fail("one Docker layer path resolves to multiple DiffIDs")

    if observed_configs != expected_configs:
        fail("Docker archive image config set differs from the final digest set")

    total_bytes = 0
    total_inodes = 0
    for layer_name in sorted(layer_diff_ids):
        expected_diff_id = layer_diff_ids[layer_name]
        blob_match = BLOB_PATH.fullmatch(layer_name)
        expected_archive_digest = (
            f"sha256:{blob_match.group('digest')}" if blob_match else expected_diff_id
        )
        with archive_member(outer, members, layer_name) as stream:
            archive_digest = f"sha256:{sha256_stream(stream)}"
        if archive_digest != expected_archive_digest:
            fail("Docker archive layer bytes do not match their content address")

        # Count the layer root and every explicit or implicit path. Repeated
        # paths inside one layer are counted once; the same path in different
        # chain layers is counted independently because Docker stores both.
        layer_paths = {"."}
        with archive_member(outer, members, layer_name) as stream:
            unpacked_digest = hashlib.sha256()
            digesting_stream = DigestingReader(open_uncompressed_layer(stream), unpacked_digest)
            with io.BufferedReader(digesting_stream, buffer_size=1024 * 1024) as checked_stream:
                try:
                    with tarfile.open(fileobj=checked_stream, mode="r|") as layer:
                        for entry in layer:
                            path = safe_relative_path(entry.name, allow_root=True)
                            if path == ".":
                                continue
                            if not any(
                                (
                                    entry.isfile(),
                                    entry.isdir(),
                                    entry.issym(),
                                    entry.islnk(),
                                    entry.ischr(),
                                    entry.isblk(),
                                    entry.isfifo(),
                                )
                            ):
                                fail("image layer contains an unsupported filesystem object")
                            parts = pathlib.PurePosixPath(path).parts
                            for index in range(1, len(parts) + 1):
                                layer_paths.add(
                                    pathlib.PurePosixPath(*parts[:index]).as_posix()
                                )
                            if entry.isfile():
                                total_bytes += entry.size
                    while checked_stream.read(1024 * 1024):
                        pass
                except (OSError, EOFError, tarfile.TarError):
                    fail("Docker archive layer cannot be decompressed or parsed")
        if f"sha256:{unpacked_digest.hexdigest()}" != expected_diff_id:
            fail("Docker archive unpacked layer bytes do not match the image DiffID")
        total_inodes += len(layer_paths)

if total_bytes <= 0 or total_inodes <= 0:
    fail("measured unpacked capacity must be positive")
print(f"{total_bytes}\t{total_inodes}")
'@
    $measurementProgram = Join-Path $Workspace 'measure-unpacked-capacity.py'
    if (Test-Path -LiteralPath $measurementProgram) {
        Fail 'capacity measurement program already exists'
    }
    Write-AsciiFile $measurementProgram @($program -split '\r?\n')

    try {
        Invoke-Quiet $Docker $saveArguments 'cannot save the final image set for capacity measurement'
        $measurementArguments = @('-I', $measurementProgram, $measurementArchive) + $configIds
        $measurement = @(Invoke-Captured $Python $measurementArguments `
            'cannot measure the final unpacked image set')
    }
    finally {
        foreach ($temporaryMeasurementFile in @($measurementArchive, $measurementProgram)) {
            if (Test-Path -LiteralPath $temporaryMeasurementFile) {
                Remove-Item -LiteralPath $temporaryMeasurementFile -Force
            }
        }
    }

    if ($measurement.Count -ne 1) {
        Fail 'unpacked image capacity measurement is malformed or exceeds 18 digits'
    }
    $measurementMatch = [Text.RegularExpressions.Regex]::Match(
        $measurement[0],
        '^([1-9][0-9]{0,17})\t([1-9][0-9]{0,17})$'
    )
    if (-not $measurementMatch.Success) {
        Fail 'unpacked image capacity measurement is malformed or exceeds 18 digits'
    }
    return [PSCustomObject]@{
        Bytes = [long]$measurementMatch.Groups[1].Value
        Inodes = [long]$measurementMatch.Groups[2].Value
        ManifestDigests = $digestToConfigId.Count
        ConfigIds = $configIds.Count
    }
}

function Assert-ImagePlatform(
    [string]$Docker,
    [string]$Image,
    [string]$ExpectedId
) {
    $format = '{{.Id}}|{{.Os}}|{{.Architecture}}'
    $inspection = @(Invoke-Captured $Docker @(
        'image', 'inspect', '--format', $format, $Image
    ) 'cannot inspect an exact image reference')
    if ($inspection.Count -ne 1 -or
        $inspection[0] -notmatch '^(sha256:[0-9a-f]{64})\|linux\|amd64$') {
        Fail 'image is not a single linux/amd64 artifact'
    }
    if ($ExpectedId -and $matches[1] -ne $ExpectedId) {
        Fail 'image config ID changed across the controlled Registry mirror'
    }
    return $matches[1]
}

function Push-And-VerifyImage(
    [string]$Docker,
    [string]$Python,
    [string]$Workspace,
    [string]$LocalImage,
    [string]$TemporaryTaggedImage,
    [string]$ExpectedDigest,
    [string]$FinalReference
) {
    $localId = Assert-ImagePlatform $Docker $LocalImage ''
    Invoke-Quiet $Docker @('tag', $LocalImage, $TemporaryTaggedImage) 'cannot create a temporary Registry tag'
    $pushOutput = @(Invoke-Captured $Docker @(
        'push', $TemporaryTaggedImage
    ) 'cannot push image to the temporary Registry')
    $digestMatches = @(
        $pushOutput |
            ForEach-Object { [Text.RegularExpressions.Regex]::Matches($_, 'digest:\s*(sha256:[0-9a-f]{64})') } |
            ForEach-Object { $_.Groups[1].Value } |
            Sort-Object -Unique
    )
    if ($digestMatches.Count -ne 1) {
        Fail 'Registry push did not return exactly one content digest'
    }
    $observedDigest = $digestMatches[0]
    if ($ExpectedDigest -and $observedDigest -ne $ExpectedDigest) {
        Fail 'controlled Registry changed a trusted Compose digest; refusing to rewrite trust'
    }
    $configId = Get-RegistryManifestConfigId `
        $Python $Workspace $TemporaryTaggedImage $observedDigest
    $temporaryRepository = $TemporaryTaggedImage.Substring(0, $TemporaryTaggedImage.LastIndexOf(':'))
    $exactTemporary = "$temporaryRepository@$observedDigest"
    Invoke-Quiet $Docker @('pull', '--platform', 'linux/amd64', $exactTemporary) `
        'cannot pull the exact digest from the temporary Registry'
    $observedId = Assert-ImagePlatform $Docker $exactTemporary $localId
    $repoDigests = Invoke-Captured $Docker @(
        'image', 'inspect', '--format', '{{range .RepoDigests}}{{println .}}{{end}}', $exactTemporary
    ) 'cannot inspect the mirrored RepoDigest'
    if ($repoDigests -notcontains $exactTemporary) {
        Fail 'temporary Registry did not preserve the exact RepoDigest'
    }
    return [PSCustomObject]@{
        Reference = "$FinalReference@$observedDigest"
        ConfigId = $configId
        LocalScanId = $observedId
        Os = 'linux'
        Architecture = 'amd64'
    }
}

function Stop-OwnedRegistry(
    [string]$Docker,
    [string]$ContainerId,
    [string]$RunId
) {
    if (-not $ContainerId) {
        return
    }
    $inspection = Read-DockerLabels $Docker 'container' $ContainerId
    if (-not $inspection.Succeeded) {
        Fail 'temporary Registry could not be inspected safely'
    }
    if ($inspection.Labels.'io.heyi.bundle-builder.run' -ne $RunId) {
        Fail 'temporary Registry ownership changed; manual cleanup is required'
    }
    & $Docker stop --time 30 $ContainerId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Fail 'temporary Registry could not be stopped safely'
    }
    & $Docker rm $ContainerId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Fail 'temporary Registry could not be removed safely'
    }
}

function Remove-OwnedRegistryIfPresent(
    [string]$Docker,
    [string]$ContainerId,
    [string]$RunId
) {
    if (-not $ContainerId) {
        return $null
    }
    $inspection = Read-DockerLabels $Docker 'container' $ContainerId
    if (-not $inspection.Succeeded) {
        return 'cannot inspect the tracked temporary Registry during cleanup'
    }
    if ($inspection.Labels.'io.heyi.bundle-builder.run' -ne $RunId) {
        return 'temporary Registry ownership changed; manual cleanup is required'
    }
    & $Docker rm --force $ContainerId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        return 'cannot remove the owned temporary Registry during cleanup'
    }
    return $null
}

function Remove-OwnedNetworkIfPresent(
    [string]$Docker,
    [string]$NetworkId,
    [string]$RunId
) {
    if (-not $NetworkId) {
        return $null
    }
    $inspection = Read-DockerLabels $Docker 'network' $NetworkId
    if (-not $inspection.Succeeded) {
        return 'cannot inspect the tracked temporary network during cleanup'
    }
    if ($inspection.Labels.'io.heyi.bundle-builder.run' -ne $RunId) {
        return 'temporary network ownership changed; manual cleanup is required'
    }
    & $Docker network rm $NetworkId 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        return 'cannot remove the owned temporary network during cleanup'
    }
    return $null
}

function Sign-And-Verify(
    [string]$OpenSsl,
    [string]$PrivateKey,
    [string]$PublicKey,
    [string]$InputFile,
    [string]$SignatureFile
) {
    Invoke-Quiet $OpenSsl @(
        'dgst', '-sha256', '-sign', $PrivateKey, '-out', $SignatureFile, $InputFile
    ) 'artifact signing failed'
    Invoke-Quiet $OpenSsl @(
        'dgst', '-sha256', '-verify', $PublicKey, '-signature', $SignatureFile, $InputFile
    ) 'artifact signature self-verification failed'
}

function New-DeterministicTar(
    [string]$Python,
    [string]$InputDirectory,
    [string]$OutputTar,
    [long]$Epoch,
    [string]$Workspace,
    [string]$ArchiveRootName
) {
    $programPath = Join-Path $Workspace 'create-deterministic-tar.py'
    if (Test-Path -LiteralPath $programPath) {
        Fail 'deterministic tar program path already exists'
    }
    $program = @'
import pathlib, re, sys, tarfile

source = pathlib.Path(sys.argv[1]).resolve(strict=True)
destination = pathlib.Path(sys.argv[2])
epoch = int(sys.argv[3])
archive_root = sys.argv[4]
if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", archive_root) is None:
    raise SystemExit("archive root name is invalid")
if destination.exists():
    raise SystemExit("destination already exists")
entries = [source, *sorted(source.rglob("*"), key=lambda p: p.relative_to(source).as_posix())]
with tarfile.open(destination, "x", format=tarfile.PAX_FORMAT) as archive:
    for path in entries:
        if path.is_symlink() or not (path.is_dir() or path.is_file()):
            raise SystemExit("unsupported filesystem object")
        relative = pathlib.PurePosixPath(archive_root)
        if path != source:
            relative /= pathlib.PurePosixPath(path.relative_to(source).as_posix())
        info = archive.gettarinfo(str(path), arcname=str(relative))
        info.uid = 0
        info.gid = 0
        info.uname = "root"
        info.gname = "root"
        info.mtime = epoch
        info.mode = 0o750 if path.is_dir() else 0o444
        info.pax_headers = {}
        if path.is_file():
            with path.open("rb") as stream:
                archive.addfile(info, stream)
        else:
            archive.addfile(info)
'@
    try {
        Write-AsciiFile $programPath @($program -split '\r?\n')
        $tarOutput = @(Invoke-Captured $Python @(
            '-I', $programPath, $InputDirectory, $OutputTar, "$Epoch", $ArchiveRootName
        ) 'deterministic POSIX tar creation failed')
    }
    finally {
        if (Test-Path -LiteralPath $programPath) {
            Remove-Item -LiteralPath $programPath -Force
        }
    }
    if ($tarOutput.Count -ne 0) {
        Fail 'deterministic POSIX tar creator returned unexpected output'
    }
}

if (-not $OutputDirectory -or -not $SigningPrivateKey -or
    -not $ImageSbomScanner -or -not $ImageSbomScannerSha256 -or
    -not $ReleaseSequence -or -not $ReleaseId) {
    Write-Error $Usage
    exit 64
}
if ($ReleaseSequence -notmatch '^[1-9][0-9]{0,17}$') {
    Fail 'release sequence must be a canonical positive integer with 1-18 digits and no leading zero'
}
if ($ReleaseId -notmatch '^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,126}[A-Za-z0-9])?$') {
    Fail 'release ID must be 1-128 characters, use only letters/digits/dot/underscore/hyphen, and start and end with a letter or digit'
}
if ($RegistryBootstrapSource -notmatch '^docker\.io/library/registry:2\.8\.3@sha256:[0-9a-f]{64}$') {
    Fail 'bootstrap Registry source must be the pinned registry:2.8.3 linux/amd64 manifest'
}
if (-not [IO.Path]::IsPathRooted($OutputDirectory) -or
    -not [IO.Path]::IsPathRooted($SigningPrivateKey) -or
    -not [IO.Path]::IsPathRooted($ImageSbomScanner)) {
    Fail 'output directory, signing key and image SBOM scanner must use absolute paths'
}

$repository = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$repository = [IO.Path]::GetFullPath($repository)
$output = [IO.Path]::GetFullPath($OutputDirectory).TrimEnd('\', '/')
$key = [IO.Path]::GetFullPath($SigningPrivateKey)
$imageSbomScannerPath = [IO.Path]::GetFullPath($ImageSbomScanner)
if (Test-IsWithin $output $repository) {
    Fail 'output directory must be outside the Git repository'
}
if (Test-IsWithin $key $repository) {
    Fail 'signing key must be outside the Git repository'
}
if (Test-IsWithin $imageSbomScannerPath $repository) {
    Fail 'image SBOM scanner must be outside the Git repository'
}
if (-not (Test-Path -LiteralPath $key -PathType Leaf)) {
    Fail 'signing key is unavailable'
}
$keyItem = Get-Item -LiteralPath $key -Force
if (($keyItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail 'signing key must not be a symbolic link or reparse point'
}
if (-not (Test-Path -LiteralPath $imageSbomScannerPath -PathType Leaf)) {
    Fail 'image SBOM scanner is unavailable'
}
$imageSbomScannerItem = Get-Item -LiteralPath $imageSbomScannerPath -Force
if (($imageSbomScannerItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
    Fail 'image SBOM scanner must not be a symbolic link or reparse point'
}
if ($ImageSbomScannerSha256 -notmatch '^[0-9a-f]{64}$' -or
    (Get-Sha256 $imageSbomScannerPath) -ne $ImageSbomScannerSha256) {
    Fail 'scanner binary SHA-256 does not match the approved digest'
}
if (Test-Path -LiteralPath $output) {
    Fail 'output directory already exists; refusing a non-atomic overwrite'
}
$outputParent = Split-Path -Parent $output
if (-not (Test-Path -LiteralPath $outputParent -PathType Container)) {
    Fail 'output parent directory does not exist'
}

$git = Resolve-NativeTool 'git.exe'
$docker = Resolve-NativeTool 'docker.exe'
$openssl = Resolve-NativeTool 'openssl.exe'
$python = Resolve-NativeTool 'python.exe'
$tar = Resolve-NativeTool 'tar.exe'
Assert-CleanRepository $git $repository
$gitHeadLines = @(Invoke-Captured $git @(
    '-C', $repository, 'rev-parse', 'HEAD'
) 'cannot resolve Git HEAD')
if ($gitHeadLines.Count -ne 1 -or $gitHeadLines[0] -notmatch '^[0-9a-f]{40}$') {
    Fail 'Git HEAD is not a full lowercase commit SHA'
}
$gitHead = $gitHeadLines[0]
$epochLines = @(Invoke-Captured $git @(
    '-C', $repository, 'show', '-s', '--format=%ct', 'HEAD'
) 'cannot resolve Git commit timestamp')
if ($epochLines.Count -ne 1 -or $epochLines[0] -notmatch '^[0-9]+$') {
    Fail 'Git commit timestamp is invalid'
}
$sourceDateEpoch = [long]$epochLines[0]

Invoke-Quiet $docker @('version') 'Docker daemon is unavailable'
Invoke-Quiet $docker @('buildx', 'version') 'Docker Buildx is unavailable'
Invoke-Quiet $openssl @('version') 'OpenSSL is unavailable'
Invoke-Quiet $python @('--version') 'Python is unavailable'
Invoke-Quiet $tar @('--version') 'POSIX tar support is unavailable'

$leaf = Split-Path -Leaf $output
$runId = [Guid]::NewGuid().ToString('N')
$lockPath = Join-Path $outputParent ".$leaf.lock"
$outputVolumeRoot = [IO.Path]::GetPathRoot($output)
if (-not $outputVolumeRoot -or $outputVolumeRoot -notmatch '^[A-Za-z]:\\$') {
    Fail 'output directory must be on a local Windows volume'
}
# Registry v2 paths can exceed the legacy Windows MAX_PATH limit when they
# inherit a user-profile/output prefix. Keep the ephemeral build workspace
# unique and at the output volume root; only the flat publish directory stays
# beside the requested output for the final atomic rename.
$workspace = Join-Path $outputVolumeRoot ".hkb-$runId"
$publish = Join-Path $outputParent ".$leaf.publish.$runId"
$lockStream = $null
$registryContainerId = ''
$registryNetworkId = ''
$published = $false
$primaryFailure = $null

try {
    try {
        $lockStream = [IO.File]::Open(
            $lockPath,
            [IO.FileMode]::OpenOrCreate,
            [IO.FileAccess]::ReadWrite,
            [IO.FileShare]::None
        )
    }
    catch [IO.IOException] {
        Fail 'another bundle build holds the output lock'
    }
    $lockStream.SetLength(0)
    $lockBytes = [Text.Encoding]::ASCII.GetBytes("pid=$PID`nrun_id=$runId`n")
    $lockStream.Write($lockBytes, 0, $lockBytes.Length)
    $lockStream.Flush($true)

    if (Test-Path -LiteralPath $workspace) {
        Fail 'temporary workspace identity collided with an existing path'
    }
    if (Test-IsWithin $workspace $repository) {
        Fail 'temporary workspace must remain outside the Git repository'
    }
    [void][IO.Directory]::CreateDirectory($workspace)
    $workspaceItem = Get-Item -LiteralPath $workspace -Force
    if (($workspaceItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
        Fail 'temporary workspace must not be a symbolic link or reparse point'
    }
    [void][IO.Directory]::CreateDirectory($publish)
    $snapshotTar = Join-Path $workspace 's.tar'
    $sourceRoot = Join-Path $workspace 's'
    [void][IO.Directory]::CreateDirectory($sourceRoot)
    Invoke-Quiet $git @(
        '-C', $repository, 'archive', '--format=tar', "--output=$snapshotTar", $gitHead
    ) 'cannot create a frozen Git HEAD snapshot'
    Invoke-Quiet $tar @('-xf', $snapshotTar, '-C', $sourceRoot) `
        'cannot extract the frozen Git HEAD snapshot'
    Remove-Item -LiteralPath $snapshotTar -Force
    Assert-RegularTree $sourceRoot

    $commonScript = Join-Path $sourceRoot 'deploy/tencent/offline-operation-common.sh'
    $composeFile = Join-Path $sourceRoot 'deploy/tencent/compose.offline.yml'
    $contractAssets = @(Get-ReleaseContractAssets $commonScript)
    $schemaHead = Get-ExpectedSchemaHead (Join-Path $sourceRoot 'app/db/schema_version.py')
    Assert-DockerfilePinned (Join-Path $sourceRoot 'Dockerfile')
    Assert-DockerfilePinned (Join-Path $sourceRoot 'web/Dockerfile')
    Assert-DockerIgnoreSecretBoundary (Join-Path $sourceRoot '.dockerignore')
    Assert-DockerIgnoreSecretBoundary (Join-Path $sourceRoot 'web/.dockerignore')
    $fixedImages = @(Get-PinnedComposeImages $composeFile)
    foreach ($fixedImage in $fixedImages) {
        $fixedWithoutDigest = Get-ReferenceWithoutDigest $fixedImage
        $fixedDigest = Get-DigestFromReference $fixedImage
        if ("$fixedWithoutDigest@$fixedDigest" -ne $fixedImage) {
            Fail 'fixed Compose reference cannot be reconstructed without losing its tag'
        }
    }
    foreach ($asset in $contractAssets) {
        $relativeSource = $asset.Substring('release/'.Length).Replace('/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath (Join-Path $sourceRoot $relativeSource) -PathType Leaf)) {
            Fail 'a canonical release asset is absent from the frozen Git HEAD'
        }
    }

    $publicKey = Join-Path $workspace 'pub.pem'
    Invoke-Quiet $openssl @('pkey', '-in', $key, '-pubout', '-out', $publicKey) `
        'signing key cannot produce a public key'
    $publicDescription = @(Invoke-Captured $openssl @(
        'pkey', '-pubin', '-in', $publicKey, '-text', '-noout'
    ) 'cannot inspect the signing public key')
    $publicText = $publicDescription -join "`n"
    if ($publicText -notmatch 'Modulus:' -or $publicText -notmatch 'Public-Key:\s*\((\d+) bit\)') {
        Fail 'signing key must be RSA so release signatures are reproducible'
    }
    if ([int]$matches[1] -lt 3072) {
        Fail 'signing RSA key must contain at least 3072 bits'
    }

    if ($DryRun) {
        Assert-CleanRepository $git $repository
        $headAfterDryRun = @(Invoke-Captured $git @(
            '-C', $repository, 'rev-parse', 'HEAD'
        ) 'cannot re-check Git HEAD')
        if ($headAfterDryRun.Count -ne 1 -or $headAfterDryRun[0] -ne $gitHead) {
            Fail 'Git HEAD changed during dry-run validation'
        }
        Write-Output 'offline-bundle-builder: DRY-RUN OK'
        Write-Output "git_sha=$gitHead"
        Write-Output "release_id=$ReleaseId"
        Write-Output "release_sequence=$ReleaseSequence"
        Write-Output "schema_head=$schemaHead"
        Write-Output "release_contract_assets=$($contractAssets.Count)"
        Write-Output "fixed_compose_images=$($fixedImages.Count)"
        Write-Output 'platform=linux/amd64'
        Write-Output 'publish_mode=atomic-directory'
        Write-Output 'REGISTRY_UNPACKED_BYTES=MEASURED_DURING_FORMAL_BUILD'
        Write-Output 'REGISTRY_UNPACKED_INODES=MEASURED_DURING_FORMAL_BUILD'
        return
    }

    Write-Output 'offline-bundle-builder: loading pinned linux/amd64 bootstrap Registry image'
    Invoke-Quiet $docker @('pull', '--platform', 'linux/amd64', $RegistryBootstrapSource) `
        'cannot pull the pinned bootstrap Registry image'
    $bootstrapLocalId = Assert-ImagePlatform $docker $RegistryBootstrapSource ''
    $bootstrapTag = "heyi-bootstrap/registry:2.8.3-amd64-$($bootstrapLocalId.Substring(7, 12))"
    Invoke-Quiet $docker @('tag', $RegistryBootstrapSource, $bootstrapTag) `
        'cannot create the bootstrap Registry transport tag'

    $artifactStem = "heyi-kb-$ReleaseId"
    $bootstrapTarName = "$artifactStem-registry-bootstrap.tar"
    $bootstrapTar = Join-Path $publish $bootstrapTarName
    Invoke-Quiet $docker @('save', '--output', $bootstrapTar, $bootstrapTag) `
        'cannot save the bootstrap Registry transport image'
    $bootstrapConfigId = Get-DockerArchiveSingleConfigId `
        -Python $python -Archive $bootstrapTar -Workspace $workspace `
        -ExpectedTag $bootstrapTag
    $bootstrapChecksum = "$bootstrapTar.sha256"
    Write-AsciiFile $bootstrapChecksum @("$(Get-Sha256 $bootstrapTar)  $bootstrapTarName")
    Sign-And-Verify $openssl $key $publicKey $bootstrapChecksum "$bootstrapChecksum.sig"

    $bundleRoot = Join-Path $workspace 'b'
    $registryData = Join-Path $bundleRoot 'registry'
    $releaseRoot = Join-Path $bundleRoot 'release'
    [void][IO.Directory]::CreateDirectory($registryData)
    [void][IO.Directory]::CreateDirectory($releaseRoot)

    foreach ($asset in $contractAssets) {
        $relative = $asset.Substring('release/'.Length)
        $windowsRelative = $relative.Replace('/', [IO.Path]::DirectorySeparatorChar)
        $source = Join-Path $sourceRoot $windowsRelative
        $destination = Join-Path $releaseRoot $windowsRelative
        [void][IO.Directory]::CreateDirectory((Split-Path -Parent $destination))
        [IO.File]::Copy($source, $destination, $false)
    }

    $networkName = "heyi-bundle-$($runId.Substring(0, 20))"
    # Docker 29 suppresses published ports on --internal networks. The Registry
    # starts behind a gate; a one-shot helper removes its default route and
    # blackholes Docker's embedded DNS listener before that gate opens. IPv6 is
    # disabled at both network and namespace scope. Disabling masquerade and ICC
    # adds defense in depth while retaining one random, loopback-only host port.
    $networkOutput = @(Invoke-Captured $docker @(
        'network', 'create', '--driver', 'bridge', '--ipv6=false',
        '--opt', 'com.docker.network.bridge.enable_ip_masquerade=false',
        '--opt', 'com.docker.network.bridge.enable_icc=false',
        '--label', "io.heyi.bundle-builder.run=$runId", $networkName
    ) 'cannot create the isolated temporary Registry network')
    if ($networkOutput.Count -ne 1 -or $networkOutput[0] -notmatch '^[0-9a-f]{64}$') {
        Fail 'temporary Registry network returned an invalid identity'
    }
    $registryNetworkId = $networkOutput[0]
    $networkPolicy = @(Invoke-Captured $docker @(
        'network', 'inspect', '--format', '{{json .}}', $registryNetworkId
    ) 'cannot inspect the temporary Registry network policy')
    try {
        $networkPolicyDocument = @($networkPolicy[0] | ConvertFrom-Json -ErrorAction Stop)
    }
    catch {
        Fail 'temporary Registry network policy is not valid Docker JSON'
    }
    if ($networkPolicy.Count -ne 1 -or $networkPolicyDocument.Count -ne 1 -or
        $networkPolicyDocument[0].Internal -ne $false -or
        $networkPolicyDocument[0].EnableIPv6 -ne $false -or
        $networkPolicyDocument[0].Options.'com.docker.network.bridge.enable_ip_masquerade' -ne
            'false' -or
        $networkPolicyDocument[0].Options.'com.docker.network.bridge.enable_icc' -ne 'false') {
        Fail 'temporary Registry network isolation options are invalid'
    }
    $containerName = "heyi-bundle-$($runId.Substring(0, 20))"
    $registryStartupCommand = (
        'while [ ! -f /tmp/heyi-network-ready ]; do sleep 0.1; done; ' +
        'exec /entrypoint.sh /etc/docker/registry/config.yml'
    )
    $containerOutput = @(Invoke-Captured $docker @(
        'run', '-d', '--pull', 'never', '--platform', 'linux/amd64',
        '--name', $containerName,
        '--label', "io.heyi.bundle-builder.run=$runId",
        '--network', $registryNetworkId,
        '--dns', '127.0.0.1',
        '--dns-search', '.',
        '--dns-opt', 'timeout:1',
        '--dns-opt', 'attempts:1',
        '--sysctl', 'net.ipv6.conf.all.disable_ipv6=1',
        '--sysctl', 'net.ipv6.conf.default.disable_ipv6=1',
        '--publish', '127.0.0.1:0:5000/tcp',
        '--cap-drop', 'ALL',
        '--security-opt', 'no-new-privileges=true',
        '--mount', "type=bind,source=$registryData,target=/var/lib/registry",
        '--entrypoint', '/bin/sh',
        $bootstrapLocalId,
        '-ceu',
        $registryStartupCommand
    ) 'cannot start the isolated temporary Registry')
    if ($containerOutput.Count -ne 1 -or $containerOutput[0] -notmatch '^[0-9a-f]{64}$') {
        Fail 'temporary Registry returned an invalid container identity'
    }
    $registryContainerId = $containerOutput[0]
    $containerNetworkPolicy = @(Invoke-Captured $docker @(
        'inspect', '--format', '{{json .HostConfig}}', $registryContainerId
    ) 'cannot inspect the temporary Registry DNS and IPv6 policy')
    try {
        $containerNetworkPolicyDocument = @(
            $containerNetworkPolicy[0] | ConvertFrom-Json -ErrorAction Stop
        )
    }
    catch {
        Fail 'temporary Registry DNS and IPv6 policy is not valid Docker JSON'
    }
    if ($containerNetworkPolicy.Count -ne 1 -or
        $containerNetworkPolicyDocument.Count -ne 1) {
        Fail 'temporary Registry DNS and IPv6 policy is not a single Docker object'
    }
    $dnsPolicy = @($containerNetworkPolicyDocument[0].Dns)
    $dnsSearchPolicy = @($containerNetworkPolicyDocument[0].DnsSearch)
    $dnsOptionsPolicy = @($containerNetworkPolicyDocument[0].DnsOptions)
    if ($dnsPolicy.Count -ne 1 -or $dnsPolicy[0] -ne '127.0.0.1' -or
        $dnsSearchPolicy.Count -ne 1 -or $dnsSearchPolicy[0] -ne '.' -or
        $dnsOptionsPolicy.Count -ne 2 -or
        $dnsOptionsPolicy[0] -ne 'timeout:1' -or
        $dnsOptionsPolicy[1] -ne 'attempts:1' -or
        $containerNetworkPolicyDocument[0].Sysctls.'net.ipv6.conf.all.disable_ipv6' -ne
            '1' -or
        $containerNetworkPolicyDocument[0].Sysctls.'net.ipv6.conf.default.disable_ipv6' -ne
            '1') {
        Fail 'temporary Registry DNS or IPv6 isolation differs from the sealed policy'
    }
    $loopbackPort = Resolve-LoopbackPublishedPort $docker $registryContainerId
    if (-not $loopbackPort -or $loopbackPort -notmatch '^127\.0\.0\.1:(\d+)$') {
        Fail 'temporary Registry is not bound to exactly one IPv4 loopback port'
    }
    $registryPort = [Text.RegularExpressions.Regex]::Match(
        $loopbackPort, ':(\d+)$'
    ).Groups[1].Value
    $registryEndpoint = "127.0.0.1:$registryPort"

    Invoke-Quiet $docker @(
        'run', '--rm', '--pull', 'never', '--platform', 'linux/amd64',
        '--label', "io.heyi.bundle-builder.run=$runId",
        '--network', "container:$registryContainerId",
        '--cap-drop', 'ALL', '--cap-add', 'NET_ADMIN',
        '--security-opt', 'no-new-privileges=true',
        '--entrypoint', '/bin/sh',
        $bootstrapLocalId, '-ceu',
        '/sbin/ip route del default; /sbin/ip route add blackhole 127.0.0.11/32 table local'
    ) 'cannot seal the temporary Registry network namespace'
    $sealedRoutes = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', 'route', 'show'
    ) 'cannot inspect the sealed temporary Registry routes')
    if ($sealedRoutes.Count -ne 1 -or
        $sealedRoutes[0] -notmatch '^[0-9.]+/[0-9]+ dev eth0 scope link(?:\s|$)' -or
        $sealedRoutes[0] -match '(^default\s|\svia\s)') {
        Fail 'temporary Registry retained a non-local network route'
    }
    $sealedLocalRoutes = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', 'route', 'show', 'table', 'local'
    ) 'cannot inspect the sealed temporary Registry local routes')
    if (($sealedLocalRoutes -join "`n") -notmatch
        '(?m)^blackhole 127\.0\.0\.11(?:\s|$)') {
        Fail 'temporary Registry did not blackhole Docker embedded DNS'
    }
    $previousErrorActionPreference = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        & $docker exec $registryContainerId /sbin/ip route get 127.0.0.11 1>$null 2>$null
        $embeddedDnsExitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $previousErrorActionPreference
    }
    if ($embeddedDnsExitCode -eq 0) {
        Fail 'Docker embedded DNS remained reachable after the network seal'
    }
    $sealedIpv6All = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/bin/cat',
        '/proc/sys/net/ipv6/conf/all/disable_ipv6'
    ) 'cannot inspect the sealed Registry IPv6 state')
    $sealedIpv6Default = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/bin/cat',
        '/proc/sys/net/ipv6/conf/default/disable_ipv6'
    ) 'cannot inspect the sealed Registry IPv6 state')
    $sealedIpv6Addresses = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', '-6', 'address', 'show'
    ) 'cannot inspect the sealed Registry IPv6 addresses')
    $sealedIpv6Routes = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', '-6', 'route', 'show', 'table', 'all'
    ) 'cannot inspect the sealed Registry IPv6 routes')
    if (($sealedIpv6All -join "`n") -ne '1' -or
        ($sealedIpv6Default -join "`n") -ne '1' -or
        $sealedIpv6Addresses.Count -ne 0 -or $sealedIpv6Routes.Count -ne 0) {
        Fail 'temporary Registry retained an IPv6 address or route'
    }
    Invoke-Quiet $docker @(
        'exec', $registryContainerId, '/bin/sh', '-ceu',
        ': > /tmp/heyi-network-ready'
    ) 'cannot open the sealed temporary Registry startup gate'

    $registryReady = $false
    for ($attempt = 0; $attempt -lt 30; $attempt++) {
        try {
            $response = Invoke-WebRequest -UseBasicParsing -Uri "http://$registryEndpoint/v2/" `
                -TimeoutSec 2
            if ($response.StatusCode -eq 200) {
                $registryReady = $true
                break
            }
        }
        catch {
            Start-Sleep -Milliseconds 500
        }
    }
    if (-not $registryReady) {
        Fail 'temporary Registry did not become ready'
    }
    $routesAfterStartup = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', 'route', 'show'
    ) 'cannot re-check the temporary Registry routes')
    if (($routesAfterStartup -join "`n") -ne ($sealedRoutes -join "`n")) {
        Fail 'temporary Registry routes changed after startup'
    }
    $localRoutesAfterStartup = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', 'route', 'show', 'table', 'local'
    ) 'cannot re-check the temporary Registry local routes')
    $ipv6AddressesAfterStartup = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', '-6', 'address', 'show'
    ) 'cannot re-check the temporary Registry IPv6 addresses')
    $ipv6RoutesAfterStartup = @(Invoke-Captured $docker @(
        'exec', $registryContainerId, '/sbin/ip', '-6', 'route', 'show', 'table', 'all'
    ) 'cannot re-check the temporary Registry IPv6 routes')
    if (($localRoutesAfterStartup -join "`n") -ne ($sealedLocalRoutes -join "`n") -or
        $ipv6AddressesAfterStartup.Count -ne 0 -or
        $ipv6RoutesAfterStartup.Count -ne 0) {
        Fail 'temporary Registry DNS or IPv6 isolation changed after startup'
    }

    $imageRecords = New-Object 'System.Collections.Generic.List[object]'
    foreach ($fixedReference in $fixedImages) {
        Write-Output 'offline-bundle-builder: mirroring one fixed Compose image'
        $sourceReference = $fixedReference.Substring('127.0.0.1:5000/heyi-mirror/'.Length)
        $expectedDigest = Get-DigestFromReference $fixedReference
        Invoke-Quiet $docker @('pull', '--platform', 'linux/amd64', $sourceReference) `
            'cannot pull a fixed Compose source image'
        [void](Assert-ImagePlatform $docker $sourceReference '')
        $finalReference = Get-ReferenceWithoutDigest $fixedReference
        $finalRepositoryAndTag = $finalReference.Substring('127.0.0.1:5000/'.Length)
        $temporaryTag = "$registryEndpoint/$finalRepositoryAndTag"
        [void]$imageRecords.Add((Push-And-VerifyImage `
            $docker $python $workspace $sourceReference $temporaryTag `
            $expectedDigest $finalReference))
    }

    $releaseTag = $gitHead.Substring(0, 12)
    $components = @(
        [PSCustomObject]@{ Name = 'api'; Context = $sourceRoot; Dockerfile = (Join-Path $sourceRoot 'Dockerfile') },
        [PSCustomObject]@{ Name = 'migration'; Context = $sourceRoot; Dockerfile = (Join-Path $sourceRoot 'Dockerfile') },
        [PSCustomObject]@{ Name = 'web'; Context = (Join-Path $sourceRoot 'web'); Dockerfile = (Join-Path $sourceRoot 'web/Dockerfile') }
    )
    $releaseReferences = @{}
    foreach ($component in $components) {
        Write-Output "offline-bundle-builder: building $($component.Name) for linux/amd64"
        $localTag = "heyi-build/$($component.Name):$releaseTag"
        Invoke-Quiet $docker @(
            'buildx', 'build', '--platform', 'linux/amd64', '--load',
            '--provenance=false', '--sbom=false',
            '--build-arg', "SOURCE_DATE_EPOCH=$sourceDateEpoch",
            '--label', "org.opencontainers.image.revision=$gitHead",
            '--label', "io.heyi.knowledgebases.component=$($component.Name)",
            '--file', $component.Dockerfile,
            '--tag', $localTag,
            $component.Context
        ) "cannot build the $($component.Name) image"
        [void](Assert-ImagePlatform $docker $localTag '')
        $temporaryTag = "$registryEndpoint/heyi-release/$($component.Name):$releaseTag"
        $finalRepository = "127.0.0.1:5000/heyi-release/$($component.Name)"
        $record = Push-And-VerifyImage `
            $docker $python $workspace $localTag $temporaryTag '' $finalRepository
        [void]$imageRecords.Add($record)
        $releaseReferences[$component.Name] = $record.Reference
    }

    Stop-OwnedRegistry $docker $registryContainerId $runId
    $registryContainerId = ''
    $networkCleanupFailure = Remove-OwnedNetworkIfPresent $docker $registryNetworkId $runId
    if ($networkCleanupFailure) {
        Fail $networkCleanupFailure
    }
    $registryNetworkId = ''
    Assert-RegularTree $registryData

    $releaseEnvironment = Join-Path $bundleRoot 'release.env'
    Write-AsciiFile $releaseEnvironment @(
        "KB_API_IMAGE=$($releaseReferences['api'])",
        "KB_MIGRATION_IMAGE=$($releaseReferences['migration'])",
        "KB_WEB_IMAGE=$($releaseReferences['web'])"
    )
    $manifestRows = @(
        $imageRecords |
            Sort-Object -Property Reference -Unique |
            ForEach-Object {
                "$($_.Reference)`t$($_.ConfigId)`t$($_.Os)`t$($_.Architecture)"
            }
    )
    if ($manifestRows.Count -ne @($imageRecords | Select-Object -ExpandProperty Reference -Unique).Count) {
        Fail 'image manifest contains duplicate or ambiguous references'
    }
    Write-AsciiFile (Join-Path $bundleRoot 'release.env.images') $manifestRows

    $savedEnvironment = @{}
    foreach ($entry in Get-ChildItem Env:) {
        if ($entry.Name -match '^(KB_|COMPOSE_|POSTGRES_|MINIO_|REDIS_|CLAMAV_)') {
            $savedEnvironment[$entry.Name] = $entry.Value
            Remove-Item -LiteralPath "Env:$($entry.Name)"
        }
    }
    try {
        $composeImages = @(Invoke-Captured $docker @(
            'compose', '--project-name', 'heyi-bundle-contract',
            '--env-file', (Join-Path $sourceRoot 'deploy/tencent/offline.env.example'),
            '--env-file', $releaseEnvironment,
            '--file', $composeFile,
            '--profile', 'ops', '--profile', 'maintenance', '--profile', 'controlled-egress',
            'config', '--images'
        ) 'cannot render the complete offline Compose image contract')
    }
    finally {
        foreach ($name in $savedEnvironment.Keys) {
            Set-Item -LiteralPath "Env:$name" -Value $savedEnvironment[$name]
        }
    }
    $rendered = @($composeImages | Where-Object { $_ } | Sort-Object -Unique)
    $manifestReferences = @($imageRecords | Select-Object -ExpandProperty Reference | Sort-Object -Unique)
    if (($rendered -join "`n") -ne ($manifestReferences -join "`n")) {
        Fail 'release image manifest differs from docker compose config --images'
    }

    # Validate the Docker archive/config identity and signed capacity before
    # running nine comparatively expensive SBOM scans.
    # Windows PowerShell 5.1 cannot reliably bind @($genericList) to an
    # [object[]] parameter and may throw "Argument types do not match".
    $imageRecordArray = $imageRecords.ToArray()
    $unpackedCapacity = Get-DeduplicatedUnpackedCapacity `
        -Docker $docker `
        -Python $python `
        -ImageRecords $imageRecordArray `
        -Workspace $workspace
    $registryUnpackedBytes = $unpackedCapacity.Bytes
    $registryUnpackedInodes = $unpackedCapacity.Inodes

    $localImageMap = Join-Path $workspace 'local-scan-images.tsv'
    $localImageRows = @(
        $imageRecords |
            Sort-Object -Property Reference -Unique |
            ForEach-Object { "$($_.Reference)`t$($_.LocalScanId)" }
    )
    if ($localImageRows.Count -ne $manifestRows.Count) {
        Fail 'local image scan map differs from the signed image manifest'
    }
    Write-AsciiFile $localImageMap $localImageRows
    $sbomGenerator = Join-Path $sourceRoot 'scripts/generate_offline_image_sboms.py'
    try {
        $sbomOutput = @(Invoke-Captured $python @(
            '-I', $sbomGenerator,
            '--artifact-root', $bundleRoot,
            '--image-manifest', (Join-Path $bundleRoot 'release.env.images'),
            '--local-image-map', $localImageMap,
            '--output-dir', (Join-Path $bundleRoot 'sbom'),
            '--scanner', $imageSbomScannerPath,
            '--scanner-sha256', $ImageSbomScannerSha256,
            '--release-id', $ReleaseId,
            '--release-git-sha', $gitHead
        ) 'cannot generate the final image SBOM set')
    }
    finally {
        if (Test-Path -LiteralPath $localImageMap) {
            Remove-Item -LiteralPath $localImageMap -Force
        }
    }
    if ($sbomOutput.Count -ne 1) {
        Fail 'image SBOM generator returned a malformed report'
    }
    try {
        $sbomReport = $sbomOutput[0] | ConvertFrom-Json
    }
    catch {
        Fail 'image SBOM generator returned invalid JSON'
    }
    if ($sbomReport.status -ne 'PASS' -or $sbomReport.image_count -ne 9 -or
        $sbomReport.index_path -ne 'sbom/image-sbom-index.json') {
        Fail 'image SBOM generator did not bind the exact nine-image release set'
    }

    $control = Join-Path $bundleRoot 'bundle.control'
    Write-AsciiFile $control @(
        "REGISTRY_BOOTSTRAP_IMAGE=$bootstrapTag",
        "REGISTRY_BOOTSTRAP_IMAGE_ID=$bootstrapConfigId",
        "RELEASE_SEQUENCE=$ReleaseSequence",
        "RELEASE_ID=$ReleaseId",
        "RELEASE_GIT_SHA=$gitHead",
        "RELEASE_SCHEMA_HEAD=$schemaHead",
        "REGISTRY_UNPACKED_BYTES=$registryUnpackedBytes",
        "REGISTRY_UNPACKED_INODES=$registryUnpackedInodes"
    )

    $checksumEntries = New-Object 'System.Collections.Generic.List[string]'
    foreach ($relative in @('bundle.control', 'release.env', 'release.env.images')) {
        $path = Join-Path $bundleRoot $relative
        [void]$checksumEntries.Add("$(Get-Sha256 $path)  $relative")
    }
    foreach ($directory in @('registry', 'release', 'sbom')) {
        $base = Join-Path $bundleRoot $directory
        foreach ($file in Get-ChildItem -LiteralPath $base -File -Force -Recurse |
            Sort-Object { $_.FullName.Substring($bundleRoot.Length + 1).Replace('\', '/') }) {
            $relative = $file.FullName.Substring($bundleRoot.Length + 1).Replace('\', '/')
            if ($relative -notmatch '^[A-Za-z0-9._/-]+$' -or $relative.Contains('//')) {
                Fail 'bundle checksum inventory contains an unsafe path'
            }
            [void]$checksumEntries.Add("$(Get-Sha256 $file.FullName)  $relative")
        }
    }
    $checksumEntries = @($checksumEntries | Sort-Object { $_.Substring(66) })
    $checksums = Join-Path $bundleRoot 'SHA256SUMS'
    Write-AsciiFile $checksums $checksumEntries
    Sign-And-Verify $openssl $key $publicKey $checksums (Join-Path $bundleRoot 'SHA256SUMS.sig')
    Assert-RegularTree $bundleRoot
    foreach ($file in Get-ChildItem -LiteralPath $bundleRoot -File -Force -Recurse) {
        $relative = $file.FullName.Substring($bundleRoot.Length + 1).Replace('\', '/')
        $allowedEnvironmentArtifacts = @('release.env', 'release.env.images')
        if (($file.Name -in @('.env', 'runtime.env')) -or
            ($file.Extension -in @('.key', '.pem', '.p12', '.pfx')) -or
            ($file.Name.EndsWith('.env', [StringComparison]::OrdinalIgnoreCase) -and
                $relative -notin $allowedEnvironmentArtifacts)) {
            Fail 'bundle contains a forbidden environment or key artifact'
        }
    }

    $bundleTarName = "$artifactStem-offline-registry-bundle.tar"
    $bundleTar = Join-Path $publish $bundleTarName
    New-DeterministicTar $python $bundleRoot $bundleTar $sourceDateEpoch `
        $workspace 'offline-registry-bundle'
    $bundleChecksum = "$bundleTar.sha256"
    Write-AsciiFile $bundleChecksum @("$(Get-Sha256 $bundleTar)  $bundleTarName")
    Sign-And-Verify $openssl $key $publicKey $bundleChecksum "$bundleChecksum.sig"

    Assert-CleanRepository $git $repository
    $headAfterBuild = @(Invoke-Captured $git @(
        '-C', $repository, 'rev-parse', 'HEAD'
    ) 'cannot re-check Git HEAD after build')
    if ($headAfterBuild.Count -ne 1 -or $headAfterBuild[0] -ne $gitHead) {
        Fail 'Git HEAD changed while the release was being built'
    }
    if (Test-Path -LiteralPath $output) {
        Fail 'output directory appeared during build; refusing overwrite'
    }
    [IO.Directory]::Move($publish, $output)
    $published = $true
    Write-Output 'offline-bundle-builder: PASS - signed artifacts published atomically'
    Write-Output "git_sha=$gitHead"
    Write-Output "release_id=$ReleaseId"
    Write-Output "release_sequence=$ReleaseSequence"
    Write-Output "schema_head=$schemaHead"
    Write-Output 'platform=linux/amd64'
    Write-Output "REGISTRY_UNPACKED_BYTES=$registryUnpackedBytes"
    Write-Output "REGISTRY_UNPACKED_INODES=$registryUnpackedInodes"
}
catch {
    $primaryFailure = $_
}
finally {
    $cleanupFailures = New-Object 'System.Collections.Generic.List[string]'
    if ($registryContainerId) {
        try {
            $cleanupFailure = Remove-OwnedRegistryIfPresent $docker $registryContainerId $runId
            if ($cleanupFailure) {
                [void]$cleanupFailures.Add($cleanupFailure)
            }
        }
        catch {
            [void]$cleanupFailures.Add('temporary Registry cleanup raised an exception')
        }
    }
    if ($registryNetworkId) {
        try {
            $cleanupFailure = Remove-OwnedNetworkIfPresent $docker $registryNetworkId $runId
            if ($cleanupFailure) {
                [void]$cleanupFailures.Add($cleanupFailure)
            }
        }
        catch {
            [void]$cleanupFailures.Add('temporary network cleanup raised an exception')
        }
    }
    if (Test-Path -LiteralPath $workspace) {
        try {
            Remove-Item -LiteralPath $workspace -Recurse -Force
        }
        catch {
            [void]$cleanupFailures.Add('temporary workspace cleanup failed')
        }
    }
    if (-not $published -and (Test-Path -LiteralPath $publish)) {
        try {
            Remove-Item -LiteralPath $publish -Recurse -Force
        }
        catch {
            [void]$cleanupFailures.Add('temporary publish directory cleanup failed')
        }
    }
    if ($null -ne $lockStream) {
        try {
            $lockStream.Dispose()
            Remove-Item -LiteralPath $lockPath -Force
        }
        catch {
            [void]$cleanupFailures.Add('output lock cleanup failed')
        }
    }
    if ($cleanupFailures.Count -ne 0) {
        if ($null -ne $primaryFailure) {
            throw ("offline-bundle-builder: build failed: " +
                "$($primaryFailure.Exception.Message); cleanup incomplete: " +
                "$($cleanupFailures -join '; ')")
        }
        throw "offline-bundle-builder: cleanup incomplete: $($cleanupFailures -join '; ')"
    }
}
if ($null -ne $primaryFailure) {
    throw $primaryFailure
}
