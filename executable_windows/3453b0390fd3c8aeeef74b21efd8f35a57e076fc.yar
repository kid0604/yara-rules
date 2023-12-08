import "pe"

rule SafeDiscv4
{
	meta:
		author = "malware-lu"
		description = "Detects SafeDiscv4 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 00 00 00 00 00 00 00 00 00 00 00 00 42 6F 47 5F }

	condition:
		$a0
}
