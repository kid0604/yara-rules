import "pe"

rule APT_WIN_Gh0st_ver : RAT
{
	meta:
		author = "@BryanNolen"
		date = "2012-12"
		type = "APT"
		version = "1.1"
		ref = "Detection of Gh0st RAT server DLL component"
		ref1 = "http://www.mcafee.com/au/resources/white-papers/foundstone/wp-know-your-digital-enemy.pdf"
		description = "Detection of Gh0st RAT server DLL component"
		os = "windows"
		filetype = "executable"

	strings:
		$library = "deflate 1.1.4 Copyright 1995-2002 Jean-loup Gailly"
		$capability = "GetClipboardData"
		$capability1 = "capCreateCaptureWindowA"
		$capability2 = "CreateRemoteThread"
		$capability3 = "WriteProcessMemory"
		$capability4 = "LsaRetrievePrivateData"
		$capability5 = "AdjustTokenPrivileges"
		$function = "ResetSSDT"
		$window = "WinSta0\\Default"
		$magic = {47 6C 6F 62 61 6C 5C [5-9] 20 25 64}

	condition:
		all of them
}
