function Invoke-ExecIntuneGraphRequest {
    <#
    .FUNCTIONALITY
        Entrypoint
    .ROLE
        Endpoint.MEM.ReadWrite
    .DESCRIPTION
        Executes allowlisted Microsoft Graph write requests for Intune policy management only.
        This is intentionally not a general Graph write proxy.
    #>
    [CmdletBinding()]
    param($Request, $TriggerMetadata)

    $APIName = $Request.Params.CIPPEndpoint
    $Headers = $Request.Headers

    $ValidationErrors = [System.Collections.Generic.List[string]]::new()

    $TenantFilter = $Request.Query.tenantFilter ??
        $Request.Query.TenantFilter ??
        $Request.Body.tenantFilter.value ??
        $Request.Body.tenantFilter ??
        $Request.Body.TenantFilter ??
        $Request.Body.tenantId ??
        $Request.Body.TenantId

    $Endpoint = $Request.Query.endpoint ??
        $Request.Query.Endpoint ??
        $Request.Body.endpoint ??
        $Request.Body.Endpoint ??
        $Request.Body.url ??
        $Request.Body.Url

    $Method = $Request.Query.method ??
        $Request.Query.Method ??
        $Request.Body.method ??
        $Request.Body.Method

    $Version = $Request.Query.version ??
        $Request.Query.Version ??
        $Request.Body.version ??
        $Request.Body.Version ??
        'beta'

    $AsAppRaw = $Request.Query.asApp ??
        $Request.Query.AsApp ??
        $Request.Body.asApp ??
        $Request.Body.AsApp ??
        $true

    $DryRunRaw = $Request.Query.dryRun ??
        $Request.Query.DryRun ??
        $Request.Body.dryRun ??
        $Request.Body.DryRun ??
        $false

    $IgnoreErrorsRaw = $Request.Query.ignoreErrors ??
        $Request.Query.IgnoreErrors ??
        $Request.Body.ignoreErrors ??
        $Request.Body.IgnoreErrors ??
        $false

    $AllowDeleteRaw = $Request.Query.allowDelete ??
        $Request.Query.AllowDelete ??
        $Request.Body.allowDelete ??
        $Request.Body.AllowDelete ??
        $false

    $ScheduleRetryRaw = $Request.Query.scheduleRetry ??
        $Request.Query.ScheduleRetry ??
        $Request.Body.scheduleRetry ??
        $Request.Body.ScheduleRetry ??
        $false

    $MaxRetriesRaw = $Request.Query.maxRetries ??
        $Request.Query.MaxRetries ??
        $Request.Body.maxRetries ??
        $Request.Body.MaxRetries ??
        3

    if ([string]::IsNullOrWhiteSpace([string]$TenantFilter)) {
        $ValidationErrors.Add('tenantFilter is required.')
    }

    if ([string]::IsNullOrWhiteSpace([string]$Endpoint)) {
        $ValidationErrors.Add('endpoint is required.')
    }

    if ([string]::IsNullOrWhiteSpace([string]$Method)) {
        $ValidationErrors.Add('method is required.')
    }

    try {
        $AsApp = [System.Convert]::ToBoolean($AsAppRaw)
        $DryRun = [System.Convert]::ToBoolean($DryRunRaw)
        $IgnoreErrors = [System.Convert]::ToBoolean($IgnoreErrorsRaw)
        $AllowDelete = [System.Convert]::ToBoolean($AllowDeleteRaw)
        $ScheduleRetry = [System.Convert]::ToBoolean($ScheduleRetryRaw)
        $MaxRetries = [int]$MaxRetriesRaw
    } catch {
        $ValidationErrors.Add('Boolean/integer parameter coercion failed. Check asApp, dryRun, ignoreErrors, allowDelete, scheduleRetry, and maxRetries.')
    }

    if ($MaxRetries -lt 0 -or $MaxRetries -gt 5) {
        $ValidationErrors.Add('maxRetries must be between 0 and 5.')
    }

    $Method = ([string]$Method).ToUpperInvariant()
    $AllowedMethods = @('POST', 'PATCH', 'PUT')

    if ($AllowDelete) {
        $AllowedMethods += 'DELETE'
    }

    if ($Method -notin $AllowedMethods) {
        if ($Method -eq 'DELETE') {
            $ValidationErrors.Add('DELETE is disabled by default. Set allowDelete=true only when intentionally deleting an allowlisted Intune policy resource.')
        } else {
            $ValidationErrors.Add("Method not allowed: $Method. Allowed methods: $($AllowedMethods -join ', ').")
        }
    }

    if ($Version -notin @('beta', 'v1.0')) {
        $ValidationErrors.Add('version must be beta or v1.0.')
    }

    $Endpoint = ([string]$Endpoint).Trim()

    if ($Endpoint -match '^https://graph\.microsoft\.com/(beta|v1\.0)/(.+)$') {
        $VersionFromEndpoint = $Matches[1]
        $EndpointFromUrl = $Matches[2]

        if (($Request.Query.version -or $Request.Query.Version -or $Request.Body.version -or $Request.Body.Version) -and $Version -ne $VersionFromEndpoint) {
            $ValidationErrors.Add("Graph version mismatch. Explicit version '$Version' does not match endpoint version '$VersionFromEndpoint'.")
        }

        $Version = $VersionFromEndpoint
        $Endpoint = $EndpointFromUrl
    } elseif ($Endpoint -match '^https?://') {
        $ValidationErrors.Add('Only Microsoft Graph URLs are allowed. Do not send external URLs.')
    }

    $Endpoint = $Endpoint.TrimStart('/')

    try {
        $Endpoint = [System.Uri]::UnescapeDataString($Endpoint)
    } catch {
        $ValidationErrors.Add('endpoint URL decoding failed.')
    }

    if ($Endpoint -match '[\r\n]') {
        $ValidationErrors.Add('endpoint must not contain CR/LF characters.')
    }

    if ($Endpoint -match '\.\.') {
        $ValidationErrors.Add('endpoint must not contain path traversal sequences.')
    }

    if ($Endpoint -match '//') {
        $ValidationErrors.Add('endpoint must not contain double slashes.')
    }

    $EndpointPath = ($Endpoint -split '\?', 2)[0]

    if ([string]::IsNullOrWhiteSpace($EndpointPath)) {
        $ValidationErrors.Add('endpoint path is empty.')
    }

    if ($EndpointPath -match '^\$batch$') {
        $ValidationErrors.Add('Nested Graph $batch calls are not allowed.')
    }

    #
    # Intune-policy-only allowlist.
    #
    # This intentionally does NOT allow broad deviceManagement/* because that would include
    # destructive device actions such as wipe, retire, reset, sync, etc.
    #
    $AllowedEndpointPatterns = @(
        # Settings catalog policies
        '^deviceManagement/configurationPolicies(?:\([^)]*\)|/[^?]+)?$',

        # Device configuration profiles
        '^deviceManagement/deviceConfigurations(?:\([^)]*\)|/[^?]+)?$',

        # Compliance policies
        '^deviceManagement/deviceCompliancePolicies(?:\([^)]*\)|/[^?]+)?$',

        # Administrative templates / group policy configs
        '^deviceManagement/groupPolicyConfigurations(?:\([^)]*\)|/[^?]+)?$',

        # Endpoint security / Intune intents
        '^deviceManagement/intents(?:\([^)]*\)|/[^?]+)?$',
        '^deviceManagement/templates(?:\([^)]*\)|/[^?]+)?$',

        # Assignment filters
        '^deviceManagement/assignmentFilters(?:\([^)]*\)|/[^?]+)?$',

        # Enrollment policy/configuration objects
        '^deviceManagement/deviceEnrollmentConfigurations(?:\([^)]*\)|/[^?]+)?$',
        '^deviceManagement/windowsAutopilotDeploymentProfiles(?:\([^)]*\)|/[^?]+)?$',

        # Intune policy sets
        '^deviceAppManagement/policySets(?:\([^)]*\)|/[^?]+)?$'
    )

    $BlockedEndpointPatterns = @(
        '^users(?:/|$)',
        '^groups(?:/|$)',
        '^directoryRoles(?:/|$)',
        '^roleManagement(?:/|$)',
        '^applications(?:/|$)',
        '^servicePrincipals(?:/|$)',
        '^oauth2PermissionGrants(?:/|$)',
        '^identity(?:/|$)',
        '^policies(?:/|$)',
        '^deviceManagement/managedDevices(?:/|$)',
        '^deviceManagement/detectedApps(?:/|$)',
        '^deviceManagement/deviceHealthScripts(?:/|$)',
        '^deviceManagement/deviceManagementScripts(?:/|$)',
        '^deviceManagement/virtualEndpoint(?:/|$)',
        '^deviceManagement/reports(?:/|$)',
        '^deviceManagement/auditEvents(?:/|$)'
    )

    foreach ($BlockedPattern in $BlockedEndpointPatterns) {
        if ($EndpointPath -match $BlockedPattern) {
            $ValidationErrors.Add("Blocked Intune/Graph endpoint: $EndpointPath")
            break
        }
    }

    $AllowedEndpoint = $false
    foreach ($AllowedPattern in $AllowedEndpointPatterns) {
        if ($EndpointPath -match $AllowedPattern) {
            $AllowedEndpoint = $true
            break
        }
    }

    if (!$AllowedEndpoint) {
        $ValidationErrors.Add("Endpoint is not in the Intune policy allowlist: $EndpointPath")
    }

    #
    # Optional: restrict DELETE further. Even if allowDelete=true, only allow deleting the same
    # allowlisted policy object types. This avoids device actions and non-policy destructive calls.
    #
    if ($Method -eq 'DELETE' -and !$AllowDelete) {
        $ValidationErrors.Add('DELETE requires allowDelete=true.')
    }

    $GraphBodyInput = $Request.Body.body ??
        $Request.Body.Body ??
        $Request.Body.graphBody ??
        $Request.Body.GraphBody

    $BodyJson = $null

    if ($Method -in @('POST', 'PATCH', 'PUT')) {
        if ($null -eq $GraphBodyInput) {
            $ValidationErrors.Add("body is required for $Method requests.")
        } elseif ($GraphBodyInput -is [string]) {
            if ([string]::IsNullOrWhiteSpace($GraphBodyInput)) {
                $ValidationErrors.Add("body must not be empty for $Method requests.")
            } else {
                try {
                    $null = $GraphBodyInput | ConvertFrom-Json -ErrorAction Stop
                    $BodyJson = $GraphBodyInput
                } catch {
                    $ValidationErrors.Add('body must be valid JSON when supplied as a string.')
                }
            }
        } else {
            try {
                $BodyJson = $GraphBodyInput | ConvertTo-Json -Depth 100 -Compress
                $null = $BodyJson | ConvertFrom-Json -ErrorAction Stop
            } catch {
                $ValidationErrors.Add('body could not be converted to valid JSON.')
            }
        }
    }

    if ($BodyJson) {
        $BodyBytes = [System.Text.Encoding]::UTF8.GetByteCount($BodyJson)
        if ($BodyBytes -gt 4194304) {
            $ValidationErrors.Add('body exceeds 4 MB Graph request limit.')
        }
    }

    #
    # Only allow safe extra headers. Never accept Authorization from caller.
    #
    $AddedHeaders = @{}
    $CallerHeaders = $Request.Body.headers ?? $Request.Body.Headers
    if ($CallerHeaders) {
        if ($CallerHeaders.'If-Match') {
            $AddedHeaders['If-Match'] = [string]$CallerHeaders.'If-Match'
        }
        if ($CallerHeaders.'Prefer') {
            $Prefer = [string]$CallerHeaders.'Prefer'
            if ($Prefer -match '^(return=representation|return=minimal)$') {
                $AddedHeaders['Prefer'] = $Prefer
            } else {
                $ValidationErrors.Add('Only Prefer: return=representation or Prefer: return=minimal are allowed.')
            }
        }
    }

    if ($ValidationErrors.Count -gt 0) {
        $ValidationMessage = $ValidationErrors -join ' '
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Blocked Intune Graph write request: $ValidationMessage" -Sev 'Warning'

        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{
                Results  = "Blocked: $ValidationMessage"
                Metadata = @{
                    tenantFilter = $TenantFilter
                    version      = $Version
                    method       = $Method
                    endpoint     = $Endpoint
                    endpointPath = $EndpointPath
                    dryRun       = $DryRun
                }
            }
        }
    }

    $GraphUri = "https://graph.microsoft.com/$Version/$Endpoint"

    $Metadata = @{
        tenantFilter = $TenantFilter
        version      = $Version
        method       = $Method
        endpoint     = $Endpoint
        endpointPath = $EndpointPath
        asApp        = $AsApp
        dryRun       = $DryRun
        allowDelete  = $AllowDelete
    }

    if ($DryRun) {
        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Dry run Intune Graph write request: $Method $EndpointPath" -Sev 'Info'

        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @{
                Results  = 'DryRun: request validated but not executed.'
                Metadata = $Metadata
            }
        }
    }

    try {
        $GraphParams = @{
            uri           = $GraphUri
            tenantid      = $TenantFilter
            type          = $Method
            AsApp         = $AsApp
            IgnoreErrors  = $IgnoreErrors
            maxRetries    = $MaxRetries
            ScheduleRetry = $ScheduleRetry
            contentType   = 'application/json; charset=utf-8'
        }

        if ($Method -ne 'DELETE') {
            $GraphParams.body = $BodyJson
        }

        if ($AddedHeaders.Count -gt 0) {
            $GraphParams.AddedHeaders = $AddedHeaders
        }

        $GraphResult = New-GraphPOSTRequest @GraphParams -ErrorAction Stop

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Executed Intune Graph write request: $Method $EndpointPath" -Sev 'Info'

        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::OK
            Body       = @{
                Results  = $GraphResult
                Metadata = $Metadata
            }
        }
    } catch {
        $ErrorMessage = Get-CippException -Exception $_

        Write-LogMessage -headers $Headers -API $APIName -tenant $TenantFilter -message "Failed Intune Graph write request: $Method $EndpointPath - $($ErrorMessage.NormalizedError)" -Sev 'Error' -LogData $ErrorMessage

        return [HttpResponseContext]@{
            StatusCode = [HttpStatusCode]::BadRequest
            Body       = @{
                Results  = "Failed: $($ErrorMessage.NormalizedError)"
                Metadata = $Metadata
            }
        }
    }
}
