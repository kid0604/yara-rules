rule CN_Honker_cleaner_cl_2
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file cl.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "523084e8975b16e255b56db9af0f9eecf174a2dd"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "cl -eventlog All/Application/System/Security" fullword ascii
		$s1 = "clear iislog error!" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <50KB and all of them
}
