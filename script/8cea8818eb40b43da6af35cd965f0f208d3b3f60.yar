rule webshell_webshells_new_pppp
{
	meta:
		description = "Web shells - generated from file pppp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "cf01cb6e09ee594545693c5d327bdd50"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "Mail: chinese@hackermail.com" fullword
		$s3 = "if($_GET[\"hackers\"]==\"2b\"){if ($_SERVER['REQUEST_METHOD'] == 'POST') { echo "
		$s6 = "Site: http://blog.weili.me" fullword

	condition:
		1 of them
}
