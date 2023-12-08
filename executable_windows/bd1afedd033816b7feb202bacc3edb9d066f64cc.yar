rule CN_Honker_DLL_passive_privilege_escalation_ws2help
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ws2help.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "e539b799c18d519efae6343cff362dcfd8f57f69"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "PassMinDll.dll" fullword ascii
		$s1 = "\\ws2help.dll" ascii

	condition:
		uint16(0)==0x5a4d and filesize <30KB and all of them
}
