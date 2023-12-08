import "pe"

rule MicroJoiner11coban2k
{
	meta:
		author = "malware-lu"
		description = "Detects the MicroJoiner11coban2k malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BE 0C 70 40 00 BB F8 11 40 00 33 ED 83 EE 04 39 2E 74 11 }

	condition:
		$a0 at pe.entry_point
}
