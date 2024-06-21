rule malware_DOPLUGSLoader
{
	meta:
		description = "DOPLUGS Loader"
		author = "JPCERT/CC Incident Response Group"
		hash = "c7e9c45b18c8ab355f1c07879cce5a3e58620dd7"
		os = "windows"
		filetype = "executable"

	strings:
		$data1 = "NimMain" ascii wide
		$enc = {8b b4 b5 e8 fb ff ff 0f b6 44 3b 08 31 f0 3d ff 00 00 00}

	condition:
		uint16(0)==0x5A4D and all of them
}
