rule Debug_cress
{
	meta:
		description = "Webshells Auto-generated - file cress.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "36a416186fe010574c9be68002a7286a"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = "\\Mithril "
		$s4 = "Mithril.exe"

	condition:
		all of them
}
