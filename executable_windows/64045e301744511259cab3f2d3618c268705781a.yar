rule APT29_wellmess_pe
{
	meta:
		description = "detect WellMess in memory"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "memory scan"
		reference = "internal research"
		hash1 = "0322c4c2d511f73ab55bf3f43b1b0f152188d7146cc67ff497ad275d9dd1c20f"
		hash2 = "8749c1495af4fd73ccfc84b32f56f5e78549d81feefb0c1d1c3475a74345f6a8 "
		os = "windows"
		filetype = "executable"

	strings:
		$botlib1 = "botlib.wellMess" ascii
		$botlib2 = "botlib.Command" ascii
		$botlib3 = "botlib.Download" ascii
		$botlib4 = "botlib.AES_Encrypt" ascii
		$dotnet1 = "WellMess" ascii
		$dotnet2 = "<;head;><;title;>" ascii wide
		$dotnet3 = "<;title;><;service;>" ascii wide
		$dotnet4 = "AES_Encrypt" ascii

	condition:
		( uint16(0)==0x5A4D) and ( all of ($botlib*) or all of ($dotnet*))
}
