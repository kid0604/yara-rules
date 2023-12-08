import "pe"

rule kryptor5
{
	meta:
		author = "malware-lu"
		description = "Detects a specific pattern at the entry point of a PE file, which may indicate the presence of the Kryptor5 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 03 [3] E9 EB 6C 58 40 FF E0 }

	condition:
		$a0 at pe.entry_point
}
