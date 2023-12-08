rule CN_Honker_HASH_PwDump7
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file PwDump7.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "93a2d7c3a9b83371d96a575c15fe6fce6f9d50d3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "%s\\SYSTEM32\\CONFIG\\SAM" fullword ascii
		$s2 = "No Users key!" fullword ascii
		$s3 = "NO PASSWORD*********************:" fullword ascii
		$s4 = "Unable to dump file %S" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <380KB and all of them
}
