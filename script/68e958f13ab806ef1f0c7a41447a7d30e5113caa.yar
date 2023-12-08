rule webshell_webshells_new_PHP1
{
	meta:
		description = "Web shells - generated from file PHP1.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "14c7281fdaf2ae004ca5fec8753ce3cb"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<[url=mailto:?@array_map($_GET[]?@array_map($_GET['f'],$_GET[/url]);?>" fullword
		$s2 = ":https://forum.90sec.org/forum.php?mod=viewthread&tid=7316" fullword
		$s3 = "@preg_replace(\"/f/e\",$_GET['u'],\"fengjiao\"); " fullword

	condition:
		1 of them
}
