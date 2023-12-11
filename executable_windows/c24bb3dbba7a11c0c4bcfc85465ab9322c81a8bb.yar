rule CN_Honker_termsrvhack
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file termsrvhack.dll"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1c456520a7b7faf71900c71167038185f5a7d312"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "The terminal server cannot issue a client license.  It was unable to issue the" wide
		$s6 = "%s\\%s\\%d\\%d" fullword wide

	condition:
		uint16(0)==0x5a4d and filesize <1052KB and all of them
}
