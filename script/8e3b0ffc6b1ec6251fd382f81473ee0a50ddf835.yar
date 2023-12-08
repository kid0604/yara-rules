rule xssshell_db
{
	meta:
		description = "Webshells Auto-generated - file db.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "cb62e2ec40addd4b9930a9e270f5b318"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s8 = "'// By Ferruh Mavituna | http://ferruh.mavituna.com"

	condition:
		all of them
}
