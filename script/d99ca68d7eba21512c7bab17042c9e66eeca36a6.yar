rule Susp_PowerShell_Sep17_1
{
	meta:
		description = "Detects suspicious PowerShell script in combo with VBS or JS "
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2017-09-30"
		score = 60
		hash1 = "8e28521749165d2d48bfa1eac685c985ac15fc9ca5df177d4efadf9089395c56"
		os = "windows"
		filetype = "script"

	strings:
		$x1 = "Process.Create(\"powershell.exe -nop -w hidden" fullword ascii nocase
		$x2 = ".Run\"powershell.exe -nop -w hidden -c \"\"IEX " ascii
		$s1 = "window.resizeTo 0,0" fullword ascii

	condition:
		( filesize <2KB and 1 of them )
}
