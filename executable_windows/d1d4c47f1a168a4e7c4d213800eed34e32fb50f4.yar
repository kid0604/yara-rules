rule malware_sakula_shellcode
{
	meta:
		description = "Sakula shellcode - taken from decoded setup.msi but may not be unique enough to identify Sakula"
		author = "David Cannings"
		os = "windows"
		filetype = "executable"

	strings:
		$opcodes01 = { 55 89 E5 E8 00 00 00 00 58 83 C0 06 C9 C3 }
		$opcodes02 = { 8B 5E 3C 8B 5C 1E 78 8B 4C 1E 20 53 8B 5C 1E 24 01 F3 }

	condition:
		any of them
}
