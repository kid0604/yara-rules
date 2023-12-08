import "pe"

rule Armadillov2xxCopyMemII
{
	meta:
		author = "malware-lu"
		description = "Detects Armadillo v2.xx CopyMemII function"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 6A ?? 8B B5 [4] C1 E6 04 8B 85 [4] 25 07 [2] 80 79 05 48 83 C8 F8 40 33 C9 8A 88 [4] 8B 95 [4] 81 E2 07 [2] 80 79 05 4A 83 CA F8 42 33 C0 8A 82 }

	condition:
		$a0 at pe.entry_point
}
