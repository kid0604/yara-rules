import "pe"

rule EXEShieldv01bv03bv03SMoKE
{
	meta:
		author = "malware-lu"
		description = "Detects EXEShieldv01bv03bv03SMoKE malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 04 00 00 00 83 60 EB 0C 5D EB 05 }

	condition:
		$a0 at pe.entry_point
}
