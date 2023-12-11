import "pe"

rule KGCryptvxx
{
	meta:
		author = "malware-lu"
		description = "Detects KGCryptvxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 5D 81 ED [4] 64 A1 30 [3] 84 C0 74 ?? 64 A1 20 [3] 0B C0 74 }

	condition:
		$a0 at pe.entry_point
}
