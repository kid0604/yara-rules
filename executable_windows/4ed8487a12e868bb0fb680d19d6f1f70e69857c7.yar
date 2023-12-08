import "pe"

rule Upackv01xv02xDwing
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Upack v01x/v02x Dwing malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 88 01 [2] AD 8B F8 95 }

	condition:
		$a0 at pe.entry_point
}
