import "pe"

rule MoleBoxv20
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of MoleBoxv2.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [4] 60 E8 4F }

	condition:
		$a0
}
