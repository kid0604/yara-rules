rule webshell_Worse_Linux_Shell
{
	meta:
		description = "Web Shell - file Worse Linux Shell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "8338c8d9eab10bd38a7116eb534b5fa2"
		os = "linux"
		filetype = "script"

	strings:
		$s0 = "system(\"mv \".$_FILES['_upl']['tmp_name'].\" \".$currentWD"

	condition:
		all of them
}
