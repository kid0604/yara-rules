import "pe"

rule MALWARE_Win_EspioLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects Espio loader and obfuscator"
		clamav_sig = "MALWARE.Win.EspioLoader"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb = /\\loader\\x64\\(Release|Debug)\\Espio\.pdb/ ascii
		$s1 = "obfuscatedPayload" fullword wide
		$s2 = "OBFUSCATEDPAYLOAD" fullword wide
		$s3 = "\\??\\C:\\Windows\\System32\\werfault.exe" fullword wide
		$s4 = "C:\\windows\\system32\\ntdll.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and ($pdb or 3 of ($s*))
}
