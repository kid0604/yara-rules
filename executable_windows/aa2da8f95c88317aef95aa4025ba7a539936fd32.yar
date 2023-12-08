import "pe"

rule VxHeloween1172
{
	meta:
		author = "malware-lu"
		description = "Detects VxHeloween1172 malware based on specific string pattern at entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 [2] 5E 81 EE [2] 56 50 06 0E 1F 8C C0 01 [2] 01 [2] 80 [4] 8B [2] A3 [2] 8A [2] A2 [2] B8 [2] CD 21 3D }

	condition:
		$a0 at pe.entry_point
}
