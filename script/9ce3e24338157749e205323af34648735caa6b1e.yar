rule Susp_PowerShell_Sep17_2
{
	meta:
		description = "Detects suspicious PowerShell script in combo with VBS or JS "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-30"
		hash1 = "e387f6c7a55b85e0675e3b91e41e5814f5d0ae740b92f26ddabda6d4f69a8ca8"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = ".Run \"powershell.exe -nop -w hidden -e " ascii
		$x2 = "FileExists(path + \"\\..\\powershell.exe\")" fullword ascii
		$x3 = "window.moveTo -4000, -4000" fullword ascii
		$s1 = "= CreateObject(\"Wscript.Shell\")" fullword ascii

	condition:
		filesize <20KB and (( uint16(0)==0x733c and 1 of ($x*)) or 2 of them )
}
