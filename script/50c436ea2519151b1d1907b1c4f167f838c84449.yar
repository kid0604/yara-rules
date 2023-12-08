rule WebShell_safe0ver
{
	meta:
		description = "PHP Webshells Github Archive - file safe0ver.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "366639526d92bd38ff7218b8539ac0f154190eb8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "$scriptident = \"$scriptTitle By Evilc0der.com\";" fullword
		$s4 = "while (file_exists(\"$lastdir/newfile$i.txt\"))" fullword
		$s5 = "else { /* <!-- Then it must be a File... --> */" fullword
		$s7 = "$contents .= htmlentities( $line ) ;" fullword
		$s8 = "<br><p><br>Safe Mode ByPAss<p><form method=\"POST\">" fullword
		$s14 = "elseif ( $cmd==\"upload\" ) { /* <!-- Upload File form --> */ " fullword
		$s20 = "/* <!-- End of Actions --> */" fullword

	condition:
		3 of them
}
