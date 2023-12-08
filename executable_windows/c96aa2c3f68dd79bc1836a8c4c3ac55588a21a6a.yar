import "pe"

rule PENinjav10DzAkRAkerTNT
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of PENinjav10DzAkRAkerTNT malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 5B 2A 40 00 BF 35 12 00 00 E8 40 12 00 00 3D 22 83 A3 C6 0F 85 67 0F 00 00 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 90 }

	condition:
		$a0 at pe.entry_point
}
