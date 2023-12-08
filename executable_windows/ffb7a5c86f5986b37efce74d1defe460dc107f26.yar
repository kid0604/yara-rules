import "pe"
import "time"

rule INDICATOR_SUSPICIOUS_EXE_WindDefender_AntiEmaulation
{
	meta:
		author = "ditekSHen"
		description = "Detects executables containing potential Windows Defender anti-emulation checks"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "JohnDoe" fullword ascii wide
		$s2 = "HAL9TH" fullword ascii wide

	condition:
		uint16(0)==0x5a4d and all of them
}
