import "pe"

rule VxVirusConstructorbased
{
	meta:
		author = "malware-lu"
		description = "Detects VxVirus Constructor based on specific byte patterns in the entry point"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { BB [2] B9 [2] 2E [4] 43 43 [2] 8B EC CC 8B [2] 81 [3] 06 1E B8 [2] CD 21 3D [4] 8C D8 48 8E D8 }
		$a1 = { E8 [2] 5D 81 [3] 06 1E E8 [2] E8 [4] 2E [6] B4 4A BB FF FF CD 21 83 [2] B4 4A CD 21 }

	condition:
		$a0 at pe.entry_point or $a1 at pe.entry_point
}
