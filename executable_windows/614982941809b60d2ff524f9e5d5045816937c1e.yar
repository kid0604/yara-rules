import "pe"

rule MAL_Trickbot_Oct19_3
{
	meta:
		description = "Detects Trickbot malware"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2019-10-02"
		hash1 = "25a4ae2a1ce6dbe7da4ba1e2559caa7ed080762cf52dba6c8b55450852135504"
		hash2 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
		hash3 = "d75561a744e3ed45dfbf25fe7c120bd24c38138ac469fd02e383dd455a540334"
		hash4 = "57b8ea2870f5176a30e6cba2d717fb3ff342f8bd36bac652dc4194a313b5fa64"
		hash5 = "e92dd00b092b435420f0996e4f557023fe1436110a11f0f61fbb628b959aac99"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "Decrypt Shell Fail" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <=2000KB and (1 of them or pe.imphash()=="4e3fbfbf1fc23f646cd40a6fe09385a7")
}
