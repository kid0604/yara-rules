rule webshell_php_list
{
	meta:
		description = "Web Shell - file list.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "922b128ddd90e1dc2f73088956c548ed"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "// list.php = Directory & File Listing" fullword
		$s2 = "    echo \"( ) <a href=?file=\" . $fichero . \"/\" . $filename . \">\" . $filena"
		$s9 = "// by: The Dark Raver" fullword

	condition:
		1 of them
}
