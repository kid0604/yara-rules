rule APT29_wellmess_elf
{
	meta:
		description = "ELF_Wellmess"
		author = "JPCERT/CC Incident Response Group"
		hash = "00654dd07721e7551641f90cba832e98c0acb030e2848e5efc0e1752c067ec07"
		os = "linux"
		filetype = "executable"

	strings:
		$botlib1 = "botlib.wellMess" ascii
		$botlib2 = "botlib.Command" ascii
		$botlib3 = "botlib.Download" ascii
		$botlib4 = "botlib.AES_Encrypt" ascii

	condition:
		( uint32(0)==0x464C457F) and all of ($botlib*)
}
