rule CN_Honker_Tuoku_script_MSSQL_
{
	meta:
		description = "Script from disclosed CN Honker Pentest Toolset - file MSSQL_.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "7097c21f92306983add3b5b29a517204cd6cd819"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "GetLoginCookie = Request.Cookies(Cookie_Login)" fullword ascii
		$s2 = "if ShellPath=\"\" Then ShellPath = \"c:\\\\windows\\\\system32\\\\cmd.exe\"" fullword ascii
		$s8 = "Set DD=CM.exec(ShellPath&\" /c \"&DefCmd)" fullword ascii

	condition:
		filesize <100KB and all of them
}
