rule CN_Honker_Pwdump7_Pwdump7
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file Pwdump7.bat"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "67d0e215c96370dcdc681bb2638703c2eeea188a"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "Pwdump7.exe >pass.txt" fullword ascii

	condition:
		filesize <1KB and all of them
}
