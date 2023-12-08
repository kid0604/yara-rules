rule WebShell_Generic_PHP_4
{
	meta:
		description = "PHP Webshells Github Archive - from files CrystalShell v.1.php, load_shell.php, nshell.php, Loaderz WEB Shell.php, stres.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		hash0 = "335a0851304acedc3f117782b61479bbc0fd655a"
		hash1 = "ca9fcfb50645dc0712abdf18d613ed2196e66241"
		hash2 = "86bc40772de71b1e7234d23cab355e1ff80c474d"
		hash3 = "36d8782d749638fdcaeed540d183dd3c8edc6791"
		hash4 = "03f88f494654f2ad0361fb63e805b6bbfc0c86de"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "if ($filename != \".\" and $filename != \"..\"){" fullword
		$s2 = "$owner[\"write\"] = ($mode & 00200) ? 'w' : '-';" fullword
		$s5 = "$owner[\"execute\"] = ($mode & 00100) ? 'x' : '-';" fullword
		$s6 = "$world[\"write\"] = ($mode & 00002) ? 'w' : '-';" fullword
		$s7 = "$world[\"execute\"] = ($mode & 00001) ? 'x' : '-';" fullword
		$s10 = "foreach ($arr as $filename) {" fullword
		$s19 = "else if( $mode & 0x6000 ) { $type='b'; }" fullword

	condition:
		all of them
}
