rule CN_Honker_Webshell_ASP_hy2006a
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file hy2006a.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "20da92b2075e6d96636f883dcdd3db4a38c01090"
		os = "windows"
		filetype = "script"

	strings:
		$s15 = "Const myCmdDotExeFile = \"command.com\"" fullword ascii
		$s16 = "If LCase(appName) = \"cmd.exe\" And appArgs <> \"\" Then" fullword ascii

	condition:
		filesize <406KB and all of them
}
