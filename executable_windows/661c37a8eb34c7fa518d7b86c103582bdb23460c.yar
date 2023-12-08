rule CN_Packed_Scanner
{
	meta:
		description = "Suspiciously packed executable"
		author = "Florian Roth"
		hash = "6323b51c116a77e3fba98f7bb7ff4ac6"
		score = 40
		date = "06.10.2014"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "kernel32.dll" fullword ascii
		$s2 = "CRTDLL.DLL" fullword ascii
		$s3 = "__GetMainArgs" fullword ascii
		$s4 = "WS2_32.DLL" fullword ascii

	condition:
		all of them and filesize <180KB and filesize >70KB
}
