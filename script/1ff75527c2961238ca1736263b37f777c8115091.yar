rule webshell_phpshell3
{
	meta:
		description = "Web Shell - file phpshell3.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "76117b2ee4a7ac06832d50b2d04070b8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "<input name=\"nounce\" type=\"hidden\" value=\"<?php echo $_SESSION['nounce'];"
		$s5 = "<p>Username: <input name=\"username\" type=\"text\" value=\"<?php echo $userna"
		$s7 = "$_SESSION['output'] .= \"cd: could not change to: $new_dir\\n\";" fullword

	condition:
		2 of them
}
