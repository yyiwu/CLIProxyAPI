param(
    [Parameter(Mandatory)]
    [ValidateNotNullOrEmpty()]
    [string]$Version,
    [string]$Image = "cli-proxy-api",
    [string]$BuildDate = [DateTime]::UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ")
)

$ErrorActionPreference = "Stop"

$Commit = git -C $PSScriptRoot rev-parse --short HEAD
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
$Commit = $Commit.Trim()

docker build `
    --file "$PSScriptRoot/Dockerfile" `
    --tag "${Image}:$Version" `
    --build-arg "VERSION=$Version" `
    --build-arg "COMMIT=$Commit" `
    --build-arg "BUILD_DATE=$BuildDate" `
    --label "org.opencontainers.image.version=$Version" `
    --label "org.opencontainers.image.created=$BuildDate" `
    $PSScriptRoot
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }
