rule CN_Honker_dedecms5_7
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file dedecms5.7.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "f9cbb25883828ca266e32ff4faf62f5a9f92c5fb"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "/data/admin/ver.txt" fullword ascii
		$s2 = "SkinH_EL.dll" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <830KB and all of them
}
