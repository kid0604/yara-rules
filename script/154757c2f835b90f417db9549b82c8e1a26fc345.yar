rule webshell_zacosmall
{
	meta:
		description = "Web Shell - file zacosmall.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5295ee8dc2f5fd416be442548d68f7a6"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "if($cmd!==''){ echo('<strong>'.htmlspecialchars($cmd).\"</strong><hr>"

	condition:
		all of them
}
