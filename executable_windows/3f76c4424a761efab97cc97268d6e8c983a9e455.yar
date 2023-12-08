import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_References_AuthApps
{
	meta:
		author = "ditekSHen"
		description = "Detects executables referencing many authentication apps. Observed in information stealers"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "WinAuth\\winauth.xml" ascii wide nocase
		$s2 = "Authy Desktop\\Local" ascii wide nocase

	condition:
		uint16(0)==0x5a4d and all of them
}
