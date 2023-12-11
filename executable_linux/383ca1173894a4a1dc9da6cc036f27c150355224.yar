import "pe"

rule MALWARE_Linux_RansomExx
{
	meta:
		author = "ditekshen"
		description = "Detects RansomEXX ransomware"
		clamav_sig = "MALWARE.Linux.Ransomware.RansomEXX"
		os = "linux"
		filetype = "executable"

	strings:
		$c1 = "crtstuff.c" fullword ascii
		$c2 = "cryptor.c" fullword ascii
		$c3 = "ransomware.c" fullword ascii
		$c4 = "logic.c" fullword ascii
		$c5 = "enum_files.c" fullword ascii
		$c6 = "readme.c" fullword ascii
		$c7 = "ctr_drbg.c" fullword ascii
		$s1 = "regenerate_pre_data" fullword ascii
		$s2 = "g_RansomHeader" fullword ascii
		$s3 = "CryptOneBlock" fullword ascii
		$s4 = "RansomLogic" fullword ascii
		$s5 = "CryptOneFile" fullword ascii
		$s6 = "encrypt_worker" fullword ascii
		$s7 = "list_dir" fullword ascii
		$s8 = "ctr_drbg_update_internal" fullword ascii

	condition:
		uint16(0)==0x457f and (5 of ($c*) or 6 of ($s*) or (3 of ($c*) and 3 of ($s*)))
}
