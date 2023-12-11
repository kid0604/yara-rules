rule WSockExpert
{
	meta:
		description = "Chinese Hacktool Set - file WSockExpert.exe"
		author = "Florian Roth"
		reference = "http://tools.zjqhr.com/"
		date = "2015-06-13"
		hash = "2962bf7b0883ceda5e14b8dad86742f95b50f7bf"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "OpenProcessCmdExecute!" fullword ascii
		$s2 = "http://www.hackp.com" fullword ascii
		$s3 = "'%s' is not a valid time!'%s' is not a valid date and time" fullword wide
		$s4 = "SaveSelectedFilterCmdExecute" fullword ascii
		$s5 = "PasswordChar@" fullword ascii
		$s6 = "WSockHook.DLL" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <2500KB and 4 of them
}
