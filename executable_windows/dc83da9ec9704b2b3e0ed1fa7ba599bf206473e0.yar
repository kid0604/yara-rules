rule CN_Honker_clearlogs
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file clearlogs.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		modified = "2023-01-27"
		score = 70
		hash = "490f3bc318f415685d7e32176088001679b0da1b"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "- http://ntsecurity.nu/toolbox/clearlogs/" ascii
		$s4 = "Error: Unable to clear log - " fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <140KB and all of them
}
