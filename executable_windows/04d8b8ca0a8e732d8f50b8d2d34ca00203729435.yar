rule iKAT_wmi_rundll
{
	meta:
		description = "This exe will attempt to use WMI to Call the Win32_Process event to spawn rundll - file wmi_rundll.exe"
		author = "Florian Roth"
		date = "05.11.14"
		score = 65
		reference = "http://ikat.ha.cked.net/Windows/functions/ikatfiles.html"
		hash = "97c4d4e6a644eed5aa12437805e39213e494d120"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "This operating system is not supported." fullword ascii
		$s1 = "Error!" fullword ascii
		$s2 = "Win32 only!" fullword ascii
		$s3 = "COMCTL32.dll" fullword ascii
		$s4 = "[LordPE]" ascii
		$s5 = "CRTDLL.dll" fullword ascii
		$s6 = "VBScript" fullword ascii
		$s7 = "CoUninitialize" fullword ascii

	condition:
		all of them and filesize <15KB
}
