import "pe"

rule MoleBoxV23XMoleStudiocom
{
	meta:
		author = "malware-lu"
		description = "Detects MoleBox v2.3.x packed MoleStudio.com"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 60 E8 4F 00 00 00 }

	condition:
		$a0 at pe.entry_point
}
