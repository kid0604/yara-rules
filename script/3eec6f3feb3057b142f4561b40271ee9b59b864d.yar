rule HYTop_DevPack_2005_alt_1
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
		os = "windows"
		filetype = "script"

	strings:
		$s7 = "theHref=encodeForUrl(mid(replace(lcase(list.path),lcase(server.mapPath(\"/\")),\"\")"
		$s8 = "scrollbar-darkshadow-color:#9C9CD3;"
		$s9 = "scrollbar-face-color:#E4E4F3;"

	condition:
		all of them
}
