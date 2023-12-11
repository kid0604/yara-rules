import "pe"

rule MALWARE_Win_TOITOIN_KritaLoader
{
	meta:
		author = "ditekSHen"
		description = "Detects TOITOIN KritaLoader"
		clamav = "ditekSHen.MALWARE.Win.Trojan.TOITOIN"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = ":\\Trabalho_2023\\OFF_2023\\" ascii
		$p2 = "DLL_Start_OK.pdb" ascii
		$s1 = "krita_main" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($p*) and 1 of ($s*))
}
