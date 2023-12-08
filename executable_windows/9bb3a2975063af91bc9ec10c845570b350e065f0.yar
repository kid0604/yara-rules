import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_Anti_WinJail
{
	meta:
		author = "ditekSHen"
		description = "Detects executables potentially checking for WinJail sandbox window"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Afx:400000:0" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
