rule BIN_Server
{
	meta:
		description = "Webshells Auto-generated - file Server.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d5aa9cbf1429bb5b8bf600335916dcd"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "configserver"
		$s1 = "GetLogicalDrives"
		$s2 = "WinExec"
		$s4 = "fxftest"
		$s5 = "upfileok"
		$s7 = "upfileer"

	condition:
		all of them
}
