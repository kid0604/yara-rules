rule php_shell : webshell
{
	meta:
		description = "Laudanum Injector Tools - file shell.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "dc5c03a21267d024ef0f5ab96a34e3f6423dfcd6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "command_hist[current_line] = document.shell.command.value;" fullword ascii
		$s2 = "if (e.keyCode == 38 && current_line < command_hist.length-1) {" fullword ascii
		$s3 = "array_unshift($_SESSION['history'], $command);" fullword ascii
		$s4 = "if (preg_match('/^[[:blank:]]*cd[[:blank:]]*$/', $command)) {" fullword ascii

	condition:
		filesize <40KB and all of them
}
