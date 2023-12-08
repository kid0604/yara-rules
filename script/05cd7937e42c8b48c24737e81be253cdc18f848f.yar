rule HYTop_DevPack_server
{
	meta:
		description = "Webshells Auto-generated - file server.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "1d38526a215df13c7373da4635541b43"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s0 = "<!-- PageServer Below -->"

	condition:
		all of them
}
