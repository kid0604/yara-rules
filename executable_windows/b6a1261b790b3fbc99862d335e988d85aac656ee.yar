import "pe"

rule UG2002Cruncherv03b3
{
	meta:
		author = "malware-lu"
		description = "Detects UG2002Cruncherv03b3 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 60 E8 [4] 5D 81 ED [4] E8 0D [16] 58 }

	condition:
		$a0 at pe.entry_point
}
