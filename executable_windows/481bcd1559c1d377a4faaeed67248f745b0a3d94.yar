import "pe"

rule EXE32Packv139
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of EXE32Packv139 packer"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 3B C0 74 02 81 83 55 3B C0 74 02 81 83 53 3B C9 74 01 BC [4] 02 81 [7] 3B DB 74 01 BE 5D 8B D5 81 ED EC 8D 40 }

	condition:
		$a0 at pe.entry_point
}
