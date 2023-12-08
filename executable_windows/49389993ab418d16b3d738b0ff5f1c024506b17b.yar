import "pe"

rule CrypKeyv5v6
{
	meta:
		author = "malware-lu"
		description = "Detects CrypKeyv5v6 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 58 83 E8 05 50 5F 57 8B F7 81 EF [4] 83 C6 39 BA [4] 8B DF B9 0B [3] 8B 06 }

	condition:
		$a0 at pe.entry_point
}
