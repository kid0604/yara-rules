import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_PWSH_AsciiEncoding_Pattern
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell scripts containing ASCII encoded files"
		os = "windows"
		filetype = "script"

	strings:
		$enc1 = "[char[]]([char]97..[char]122)" ascii
		$enc2 = "[char[]]([char]65..[char]90)" ascii
		$s1 = ".DownloadData($" ascii
		$s2 = "[Net.SecurityProtocolType]::TLS12" ascii
		$s3 = "::WriteAllBytes($" ascii
		$s4 = "::FromBase64String($" ascii
		$s5 = "Get-Random" ascii

	condition:
		1 of ($enc*) and 4 of ($s*) and filesize <2500KB
}
