rule CN_Honker_Webshell_jspshell2
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jspshell2.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "cc7bc1460416663012fc93d52e2078c0a277ff79"
		os = "windows"
		filetype = "script"

	strings:
		$s10 = "if (cmd == null) cmd = \"cmd.exe /c set\";" fullword ascii
		$s11 = "if (program == null) program = \"cmd.exe /c net start > \"+SHELL_DIR+\"/Log.txt" ascii

	condition:
		filesize <424KB and all of them
}
