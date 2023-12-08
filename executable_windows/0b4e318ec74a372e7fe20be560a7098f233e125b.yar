rule CN_Honker_MSTSC_can_direct_copy
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file MSTSC_can_direct_copy.EXE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2022-12-21"
		score = 70
		hash = "2f3cbfd9f82f8abafdb1d33235fa6bfa1e1f71ae"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "srv\\newclient\\lib\\win32\\obj\\i386\\mstsc.pdb" ascii
		$s2 = "Clear Password" fullword wide
		$s3 = "/migrate -- migrates legacy connection files that were created with " fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <600KB and all of them
}
