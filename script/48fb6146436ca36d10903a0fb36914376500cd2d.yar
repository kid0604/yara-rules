rule webshell_webshells_new_php6
{
	meta:
		description = "Web shells - generated from file php6.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "ea75280224a735f1e445d244acdfeb7b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "array_map(\"asx73ert\",(ar"
		$s3 = "preg_replace(\"/[errorpage]/e\",$page,\"saft\");" fullword
		$s4 = "shell.php?qid=zxexp  " fullword

	condition:
		1 of them
}
