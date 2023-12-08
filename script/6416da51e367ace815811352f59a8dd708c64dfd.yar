rule HYTop_AppPack_2005
{
	meta:
		description = "Webshells Auto-generated - file 2005.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "63d9fd24fa4d22a41fc5522fc7050f9f"
		os = "windows"
		filetype = "script"

	strings:
		$s6 = "\" onclick=\"this.form.sqlStr.value='e:\\hytop.mdb"

	condition:
		all of them
}
