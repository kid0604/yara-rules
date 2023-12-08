import "time"
import "pe"

rule INDICATOR_SUSPICIOUS_PWS_CaptureBrowserPlugins
{
	meta:
		author = "ditekSHen"
		description = "Detects PowerShell script with browser plugins capture capability"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "$env:APPDATA +" ascii nocase
		$s2 = "[\\w-]{24}\\.[\\w-]{6}\\.[\\w-]{27}|mfa\\.[\\w-]{84}" ascii nocase
		$s3 = "\\leveldb" ascii nocase
		$o1 = ".Match(" ascii nocase
		$o2 = ".Contains(" ascii nocase
		$o3 = ".Add(" ascii nocase

	condition:
		2 of ($s*) and 2 of ($o*)
}
