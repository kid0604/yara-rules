rule CN_Honker_dirdown_dirdown
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dirdown.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2022-12-21"
		score = 70
		hash = "7b8d51c72841532dded5fec7e7b0005855b8a051"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Decompress\\obj\\Release\\Decompress.pdb" ascii
		$s1 = "Decompress.exe" fullword wide
		$s5 = "Get8Bytes" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <45KB and all of them
}
