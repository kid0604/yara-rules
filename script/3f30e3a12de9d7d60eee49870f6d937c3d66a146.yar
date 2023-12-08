rule FSO_s_reader
{
	meta:
		description = "Webshells Auto-generated - file reader.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b598c8b662f2a1f6cc61f291fb0a6fa2"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s2 = "mailto:mailbomb@hotmail."

	condition:
		all of them
}
