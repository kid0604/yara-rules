rule Explosive_EXE : APT
{
	meta:
		description = "Explosion/Explosive Malware - Volatile Cedar APT"
		author = "Check Point Software Technologies Inc."
		os = "windows"
		filetype = "executable"

	strings:
		$DLD_S = "DLD-S:"
		$DLD_E = "DLD-E:"

	condition:
		all of them and uint16(0)==0x5A4D
}
