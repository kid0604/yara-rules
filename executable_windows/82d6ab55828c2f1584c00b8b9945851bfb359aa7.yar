rule CN_Honker_ms10048_x64
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file ms10048-x64.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "418bec3493c85e3490e400ecaff5a7760c17a0d0"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "[ ] Creating evil window" fullword ascii
		$s2 = "[+] Set to %d exploit half succeeded" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <125KB and all of them
}
