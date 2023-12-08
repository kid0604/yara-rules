import "pe"

rule MALWARE_Win_TOITOIN_InjectorDLL
{
	meta:
		author = "ditekSHen"
		description = "Detects TOITOIN InjectorDLL"
		clamav = "ditekSHen.MALWARE.Win.Trojan.TOITOIN"
		os = "windows"
		filetype = "executable"

	strings:
		$p1 = ":\\Trabalho_2023\\OFF_2023\\" ascii
		$p2 = "DLL_START_IN.pdb" ascii
		$s1 = ".ini" fullword ascii
		$s2 = "\\users\\Public\\Documents\\" fullword ascii

	condition:
		uint16(0)==0x5a4d and (1 of ($p*) and all of ($s*))
}
