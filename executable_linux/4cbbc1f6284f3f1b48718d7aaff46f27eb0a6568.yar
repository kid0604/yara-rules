rule Lazarus_packer_upxmems
{
	meta:
		description = "ELF malware packer based UPX in Lazarus"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "f789e1895ce24da8d7b7acef8d0302ae9f90dab0c55c22b03e452aeba55e1d21"
		os = "linux"
		filetype = "executable"

	strings:
		$code1 = { 47 2C E8 3C 01 77 [10-14] 86 C4 C1 C0 10 86 C4 }
		$code2 = { 81 FD 00 FB FF FF 83 D1 02 8D }
		$sig = "MEMS" ascii

	condition:
		all of ($code*) and #sig>=3 and uint32(0x98)==0x534d454d
}
