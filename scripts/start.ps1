[CmdletBinding()]
param(
    [string]$EnvFile = ".env.kb",
    [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$envPath = if ([System.IO.Path]::IsPathRooted($EnvFile)) {
    $EnvFile
} else {
    Join-Path $repoRoot $EnvFile
}

if (-not (Test-Path -LiteralPath $envPath -PathType Leaf)) {
    throw "Environment file not found: $envPath. Copy .env.example to .env.kb first."
}

Push-Location $repoRoot
try {
    if (-not $SkipBuild) {
        # Docker Buildx on Windows can reject non-ASCII context paths. Build
        # from a unique ASCII temp context, then let Compose reuse the image.
        $tempRoot = [System.IO.Path]::GetFullPath([System.IO.Path]::GetTempPath())
        $separator = [System.IO.Path]::DirectorySeparatorChar
        if (-not $tempRoot.EndsWith($separator)) {
            $tempRoot += $separator
        }
        $buildContext = Join-Path $tempRoot ("enterprise-kb-build-" + [guid]::NewGuid())
        [void](New-Item -ItemType Directory -Path $buildContext)
        try {
            Copy-Item -LiteralPath ".\Dockerfile", ".\pyproject.toml", ".\uv.lock", ".\alembic.ini", ".\.dockerignore" -Destination $buildContext -Force
            Copy-Item -LiteralPath ".\app" -Destination $buildContext -Recurse -Force
            Copy-Item -LiteralPath ".\alembic" -Destination $buildContext -Recurse -Force

            & docker build -t enterprise-knowledge-base-api:local $buildContext
            if ($LASTEXITCODE -ne 0) {
                throw "docker build failed with exit code $LASTEXITCODE"
            }
        } finally {
            if (Test-Path -LiteralPath $buildContext) {
                $resolvedContext = [System.IO.Path]::GetFullPath($buildContext)
                if (-not $resolvedContext.StartsWith($tempRoot, [System.StringComparison]::OrdinalIgnoreCase)) {
                    throw "Refusing to remove a build context outside the temp directory: $resolvedContext"
                }
                Remove-Item -LiteralPath $resolvedContext -Recurse -Force
            }
        }
    }

    & docker compose --env-file $envPath up --no-build -d
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose up failed with exit code $LASTEXITCODE"
    }
    & docker compose --env-file $envPath ps
    if ($LASTEXITCODE -ne 0) {
        throw "docker compose ps failed with exit code $LASTEXITCODE"
    }
} finally {
    Pop-Location
}
