rule APT29_csloader_code
{
	meta:
		description = "CobaltStrike loader using APT29"
		author = "JPCERT/CC Incident Response Group"
		hash = "459debf426444ec9965322ba3d61c5ada0d95db54c1787f108d4d4ad2c851098"
		hash = "a0224574ed356282a7f0f2cac316a7a888d432117e37390339b73ba518ba5d88"
		hash = "791c28f482358c952ff860805eaefc11fd57d0bf21ec7df1b9781c7e7d995ba3"
		os = "windows"
		filetype = "executable"

	strings:
		$size = { 41 B8 08 02 00 00 }
		$process = "explorer.exe" wide
		$resource1 = "docx" wide
		$resource2 = "BIN" wide
		$command1 = "C:\\Windows\\System32\\cmd.exe /C ping 8.8.8.8 -n 3  && del /F \"%s\"" wide
		$command2 = "C:\\Windows\\System32\\cmd.exe /k ping 8.8.8.8 -n 3  && del /F \"%s\"" wide
		$pdb = "C:\\Users\\jack\\viewer\\bin\\viewer.pdb" ascii

	condition:
		uint16(0)==0x5A4D and uint32( uint32(0x3c))==0x00004550 and ((#size>=4 and $process and 1 of ($command*) and 1 of ($resource*)) or $pdb)
}
