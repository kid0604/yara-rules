import "pe"

rule MaskPE16yzkzero
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of MaskPE16yzkzero malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 36 81 2C 24 [3] 00 C3 60 }

	condition:
		$a0
}
