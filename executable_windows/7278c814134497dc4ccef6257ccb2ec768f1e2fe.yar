import "pe"

rule VxKeypress1212
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern of keypresses in a PE file"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] E8 [2] E8 [2] E8 [4] E8 [4] E8 [4] EA [4] 1E 33 DB 8E DB BB }

	condition:
		$a0 at pe.entry_point
}
