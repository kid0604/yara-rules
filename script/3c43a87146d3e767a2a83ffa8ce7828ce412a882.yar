import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_PWSH_PasswordCredential_RetrievePassword
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell content designed to retrieve passwords from host"
		os = "windows"
		filetype = "script"

	strings:
		$namespace = "Windows.Security.Credentials.PasswordVault" ascii wide nocase
		$method1 = "RetrieveAll()" ascii wide nocase
		$method2 = ".RetrievePassword()" ascii wide nocase

	condition:
		$namespace and 1 of ($method*)
}
