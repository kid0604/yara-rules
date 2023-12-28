rule darkhotel_isyssdownloader_pdbs
{
	meta:
		description = "detect isyss downloader"
		author = "JPCERT/CC Incident Response Group"
		rule_usage = "PE file search"
		reference = "internal research"
		hash1 = "94c5a16cd1b6af3d545b1d60dff38dc8ad683c6e122fb577d628223dd532ab5a"
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = {0F 84 [2-10] B8 AB AA AA 2A F7 ?? 8B C2 C1 ?? 1F 03 C2 [2-10] 03 D2 2B F2 46 83 ?? 01}
		$pdb1 = "C:\\Code\\india_source\\80.83\\c_isyss\\Release\\isyss.pdb" ascii fullword
		$pdb2 = "\\Release\\isyss.pdb" ascii wide
		$pdb3 = "C:\\Code\\india_source\\" ascii wide

	condition:
		( uint16(0)==0x5A4D) and ( filesize <2MB) and ((1 of ($pdb*)) or ($b1))
}
