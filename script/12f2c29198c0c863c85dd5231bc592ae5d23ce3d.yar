rule webshell_Java_Shell
{
	meta:
		description = "Web Shell - file Java Shell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "36403bc776eb12e8b7cc0eb47c8aac83"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "public JythonShell(int columns, int rows, int scrollback) {" fullword
		$s9 = "this(null, Py.getSystemState(), columns, rows, scrollback);" fullword

	condition:
		1 of them
}
