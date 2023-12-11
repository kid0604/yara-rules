rule FSO_s_sincap
{
	meta:
		description = "Webshells Auto-generated - file sincap.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "dc5c2c2392b84a1529abd92e98e9aa5b"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "    <font color=\"#E5E5E5\" style=\"font-size: 8pt; font-weight: 700\" face=\"Arial\">"
		$s4 = "<body text=\"#008000\" bgcolor=\"#808080\" topmargin=\"0\" leftmargin=\"0\" rightmargin="

	condition:
		all of them
}
