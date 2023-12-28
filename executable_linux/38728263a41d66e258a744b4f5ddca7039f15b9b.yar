rule BlackTech_PLEAD_elf
{
	meta:
		description = "ELF PLEAD"
		author = "JPCERT/CC Incident Response Group"
		hash = "f704303f3acc2fd090145d5ee893914734d507bd1e6161f82fb34d45ab4a164b"
		os = "linux"
		filetype = "executable"

	strings:
		$ioctl = "ioctl TIOCSWINSZ error"
		$class1 = "CPortForwardManager"
		$class2 = "CRemoteShell"
		$class3 = "CFileManager"
		$lzo = { 81 ?? FF 07 00 00 81 ?? 1F 20 00 00 }

	condition:
		3 of them
}
