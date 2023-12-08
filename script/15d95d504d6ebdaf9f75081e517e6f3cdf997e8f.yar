rule webshell_webshells_new_php2
{
	meta:
		description = "Web shells - generated from file php2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "fbf2e76e6f897f6f42b896c855069276"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<?php $s=@$_GET[2];if(md5($s.$s)=="

	condition:
		all of them
}
