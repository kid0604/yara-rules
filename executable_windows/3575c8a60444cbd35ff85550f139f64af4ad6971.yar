import "pe"

rule VBOXv43v46
{
	meta:
		author = "malware-lu"
		description = "Detects VBOXv43v46 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 8B C5 }
		$a1 = { 90 03 C4 33 C4 33 C5 2B C5 33 C5 8B C5 [2] 2B C5 48 [2] 0B C0 86 E0 8C E0 [2] 8C E0 86 E0 03 C4 40 }

	condition:
		$a0 or $a1
}
