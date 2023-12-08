import "pe"

rule MALWARE_Win_Salfram
{
	meta:
		author = "ditekSHen"
		description = "Detects Salfram executables"
		snort2_sid = "920085-920087"
		snort3_sid = "920085"
		clamav_sig = "MALWARE.Win.Trojan.Salfram"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "!This Salfram cannot be run in DOS mode." fullword ascii

	condition:
		uint16(0)==0x5a4d and all of them
}
