import "pe"

rule VxEddie2100
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 4F 4F 0E E8 [2] 47 47 1E FF [2] CB E8 [2] 84 C0 [2] 50 53 56 57 1E 06 B4 51 CD 21 8E C3 [7] 8B F2 B4 2F CD 21 AC }

	condition:
		$a0 at pe.entry_point
}
