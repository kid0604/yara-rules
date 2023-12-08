import "pe"

rule Cruncherv10
{
	meta:
		author = "malware-lu"
		description = "Detects the presence of Cruncher v1.0 malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { 2E [4] 2E [3] B4 30 CD 21 3C 03 73 ?? BB [2] 8E DB 8D [3] B4 09 CD 21 06 33 C0 50 CB }

	condition:
		$a0 at pe.entry_point
}
