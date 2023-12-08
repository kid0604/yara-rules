import "pe"

rule BeRoTinyPascalBeRo
{
	meta:
		author = "malware-lu"
		description = "Detects BeRoTinyPascalBeRo malware"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E9 [4] 20 43 6F 6D 70 69 6C 65 64 20 62 79 3A 20 42 65 52 6F 54 69 6E 79 50 61 73 63 61 6C 20 2D 20 28 43 29 20 43 6F 70 79 72 69 67 68 74 20 32 30 30 36 2C 20 42 65 6E 6A 61 6D 69 6E 20 27 42 65 52 6F 27 20 52 6F 73 73 65 61 75 78 20 }

	condition:
		$a0 at pe.entry_point
}
