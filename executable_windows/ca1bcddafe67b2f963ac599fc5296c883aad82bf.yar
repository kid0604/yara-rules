rule CN_Honker_HASH_32
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file 32.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bf4a8b4b3e906e385feab5ea768f604f64ba84ea"
		os = "windows"
		filetype = "executable"

	strings:
		$s5 = "[Undefined OS version]  Major: %d Minor: %d" fullword ascii
		$s8 = "Try To Run As Administrator ..." fullword ascii
		$s9 = "Specific LUID NOT found" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <240KB and all of them
}
