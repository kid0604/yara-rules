rule VSSown_VBS
{
	meta:
		description = "Detects VSSown.vbs script - used to export shadow copy elements like NTDS to take away and crack elsewhere"
		author = "Florian Roth"
		date = "2015-10-01"
		score = 75
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "Select * from Win32_Service Where Name ='VSS'" ascii
		$s1 = "Select * From Win32_ShadowCopy" ascii
		$s2 = "cmd /C mklink /D " ascii
		$s3 = "ClientAccessible" ascii
		$s4 = "WScript.Shell" ascii
		$s5 = "Win32_Process" ascii

	condition:
		all of them
}
