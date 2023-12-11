rule webshell_iMHaPFtp_2
{
	meta:
		description = "Web Shell - file iMHaPFtp.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "12911b73bc6a5d313b494102abcf5c57"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s8 = "if ($l) echo '<a href=\"' . $self . '?action=permission&amp;file=' . urlencode($"
		$s9 = "return base64_decode('R0lGODlhEQANAJEDAMwAAP///5mZmf///yH5BAHoAwMALAAAAAARAA0AAA"

	condition:
		1 of them
}
