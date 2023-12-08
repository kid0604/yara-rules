import "pe"

rule SOFTWrapperforWin9xNTEvaluationVersion
{
	meta:
		author = "malware-lu"
		description = "Detects a specific wrapper used for Win9x/NT evaluation version"
		os = "windows"
		filetype = "executable"

	strings:
		$a0 = { E8 00 00 00 00 5D 8B C5 2D [3] 00 50 81 ED 05 00 00 00 8B C5 2B 85 03 0F 00 00 89 85 03 0F 00 00 8B F0 03 B5 0B 0F 00 00 8B F8 03 BD 07 0F 00 00 83 7F 0C 00 74 2B 56 57 8B 7F 10 03 F8 8B 76 10 03 F0 83 3F 00 74 0C 8B 1E 89 1F 83 C6 04 83 C7 04 EB EF }

	condition:
		$a0 at pe.entry_point
}
