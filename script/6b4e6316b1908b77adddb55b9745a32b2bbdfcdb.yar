rule WebShell_simple_cmd
{
	meta:
		description = "PHP Webshells Github Archive - file simple_cmd.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "466a8caf03cdebe07aa16ad490e54744f82e32c2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<input type=TEXT name=\"-cmd\" size=64 value=\"<?=$cmd?>\" " fullword
		$s2 = "<title>G-Security Webshell</title>" fullword
		$s4 = "<? if($cmd != \"\") print Shell_Exec($cmd);?>" fullword
		$s6 = "<? $cmd = $_REQUEST[\"-cmd\"];?>" fullword

	condition:
		1 of them
}
