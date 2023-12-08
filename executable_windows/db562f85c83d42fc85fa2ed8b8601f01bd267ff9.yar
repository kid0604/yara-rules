rule Mithril_v1_45_Mithril
{
	meta:
		description = "Webshells Auto-generated - file Mithril.exe"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f1484f882dc381dde6eaa0b80ef64a07"
		os = "windows"
		filetype = "executable"

	strings:
		$s2 = "cress.exe"
		$s7 = "\\Debug\\Mithril."

	condition:
		all of them
}
