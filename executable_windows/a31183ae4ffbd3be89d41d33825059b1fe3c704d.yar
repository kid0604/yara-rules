import "pe"

rule CrypWrapvxx
{
	meta:
		author = "malware-lu"
		description = "Detects CrypWrapvxx malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 B8 [3] E8 90 02 [2] 83 F8 ?? 75 07 6A ?? E8 [4] FF 15 49 8F 40 ?? A9 [3] 80 74 0E }

	condition:
		$a0 at pe.entry_point
}
