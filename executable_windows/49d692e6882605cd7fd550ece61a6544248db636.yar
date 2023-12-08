rule winshell
{
	meta:
		description = "Webshells Auto-generated - file winshell.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "3144410a37dd4c29d004a814a294ea26"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunServices"
		$s1 = "WinShell Service"
		$s2 = "__GLOBAL_HEAP_SELECTED"
		$s3 = "__MSVCRT_HEAP_SELECT"
		$s4 = "Provide Windows CmdShell Service"
		$s5 = "URLDownloadToFileA"
		$s6 = "RegisterServiceProcess"
		$s7 = "GetModuleBaseNameA"
		$s8 = "WinShell v5.0 (C)2002 janker.org"

	condition:
		all of them
}
