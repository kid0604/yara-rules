import "pe"

rule Crunch5Fusion4
{
	meta:
		author = "malware-lu"
		description = "Detects the Crunch5Fusion4 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 15 03 [3] 06 [11] 68 [4] 55 E8 }

	condition:
		$a0
}
