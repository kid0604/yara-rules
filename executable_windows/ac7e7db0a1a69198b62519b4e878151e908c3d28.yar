import "pe"

rule ExeStealth275aWebtoolMaster
{
	meta:
		author = "malware-lu"
		description = "Detects the ExeStealth275aWebtoolMaster malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { EB 58 53 68 61 72 65 77 61 72 65 2D 56 65 72 73 69 6F 6E 20 45 78 65 53 74 65 61 6C 74 68 2C 20 63 6F 6E 74 61 63 74 20 73 75 70 70 6F 72 74 40 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 2E 63 6F 6D 20 2D 20 77 77 77 2E 77 65 62 74 6F 6F 6C 6D 61 73 74 65 72 }

	condition:
		$a0 at pe.entry_point
}
