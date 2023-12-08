import "pe"

rule PrivateEXEProtector18
{
	meta:
		author = "malware-lu"
		description = "Detects PrivateEXEProtector version 18"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB DC EE 0D 76 D9 D0 8D 16 85 D8 90 D9 D0 }

	condition:
		$a0
}
