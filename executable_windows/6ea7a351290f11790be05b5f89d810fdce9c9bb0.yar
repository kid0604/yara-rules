import "pe"

rule EXE32Packv13x
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of EXE32Packv13x malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 3B ?? 74 02 81 83 55 3B ?? 74 02 81 ?? 53 3B ?? 74 01 [5] 02 81 [2] E8 [4] 3B 74 01 ?? 5D 8B D5 81 ED }

	condition:
		$a0 at pe.entry_point
}
