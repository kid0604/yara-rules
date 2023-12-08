rule webshell_webshells_new_xxx_alt_1
{
	meta:
		description = "Web shells - generated from file xxx.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "0e71428fe68b39b70adb6aeedf260ca0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "<?php array_map(\"ass\\x65rt\",(array)$_REQUEST['expdoor']);?>" fullword

	condition:
		all of them
}
