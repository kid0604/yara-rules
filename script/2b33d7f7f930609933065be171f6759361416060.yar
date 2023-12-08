rule FSO_s_indexer_2
{
	meta:
		description = "Webshells Auto-generated - file indexer.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "135fc50f85228691b401848caef3be9e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s5 = "<td>Nerden :<td><input type=\"text\" name=\"nerden\" size=25 value=index.html></td>"

	condition:
		all of them
}
