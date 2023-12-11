rule CN_Honker_GetPass_GetPass
{
	meta:
		description = "Sample from CN Honker Pentest Toolset - file GetPass.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "d18d952b24110b83abd17e042f9deee679de6a1a"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "\\only\\Desktop\\" ascii
		$s2 = "To Run As Administuor" ascii
		$s3 = "Key to EXIT ... & pause > nul" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <300KB and all of them
}
