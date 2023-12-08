rule webshell_webshells_new_PHP_alt_1
{
	meta:
		description = "Web shells - generated from file PHP.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "a524e7ae8d71e37d2fd3e5fbdab405ea"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "echo \"<font color=blue>Error!</font>\";" fullword
		$s2 = "<input type=\"text\" size=61 name=\"f\" value='<?php echo $_SERVER[\"SCRIPT_FILE"
		$s5 = " - ExpDoor.com</title>" fullword
		$s10 = "$f=fopen($_POST[\"f\"],\"w\");" fullword
		$s12 = "<textarea name=\"c\" cols=60 rows=15></textarea><br>" fullword

	condition:
		1 of them
}
