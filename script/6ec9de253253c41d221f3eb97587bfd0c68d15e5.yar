rule webshell_WinX_Shell
{
	meta:
		description = "Web Shell - file WinX Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "17ab5086aef89d4951fe9b7c7a561dda"
		os = "windows"
		filetype = "script"

	strings:
		$s5 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">Filenam"
		$s8 = "print \"<font face=\\\"Verdana\\\" size=\\\"1\\\" color=\\\"#990000\\\">File: </"

	condition:
		all of them
}
