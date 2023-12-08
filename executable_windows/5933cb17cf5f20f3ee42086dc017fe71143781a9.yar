rule CN_Honker_DictionaryGenerator
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file DictionaryGenerator.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "b3071c64953e97eeb2ca6796fab302d8a77d27bc"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "`PasswordBuilder" fullword ascii
		$s2 = "cracker" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <3650KB and all of them
}
