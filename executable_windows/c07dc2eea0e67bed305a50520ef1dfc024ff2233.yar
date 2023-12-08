import "pe"

rule kryptor6
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate the presence of a certain type of malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 03 [3] E9 EB 68 58 33 D2 74 02 E9 E9 40 42 75 02 }

	condition:
		$a0 at pe.entry_point
}
