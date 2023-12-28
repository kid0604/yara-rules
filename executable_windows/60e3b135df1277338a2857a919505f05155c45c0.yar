rule BlackTech_SelfMakeLoader_str
{
	meta:
		description = "SelfMake(SpiderPig) Loader in BlackTech"
		author = "JPCERT/CC Incident Response Group"
		hash = "2657ca121a3df198635fcc53efb573eb069ff2535dcf3ba899f68430caa2ffce"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = { 73 65 6C 66 6D 61 6B 65 3? 41 70 70 }
		$s2 = "fixmeconfig"
		$s3 = "[+] config path:%s"
		$cmp_magic_num = { 81 7C ?? ?? (D0 D9 FE E1 | EE D8 FF E0) }

	condition:
		uint16(0)==0x5A4D and ( all of ($s*) or $cmp_magic_num)
}
