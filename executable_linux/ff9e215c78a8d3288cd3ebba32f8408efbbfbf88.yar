rule apt_nix_elf_Derusbi_Linux_SharedMemCreation
{
	meta:
		Author = "@seifreed"
		description = "Detects the creation of shared memory by the Derusbi Linux variant of APT malware"
		os = "linux"
		filetype = "executable"

	strings:
		$byte1 = { B6 03 00 00 ?? 40 00 00 00 ?? 0D 5F 01 82 }

	condition:
		( uint32(0)==0x464C457F) and ( any of them )
}
