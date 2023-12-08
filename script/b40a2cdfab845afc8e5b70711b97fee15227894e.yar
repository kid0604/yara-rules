rule APT_WebShell_Tiny_1
{
	meta:
		description = "Detetcs a tiny webshell involved in the Australian Parliament House network compromise"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://twitter.com/cyb3rops/status/1097423665472376832"
		date = "2019-02-18"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "eval(" ascii wide

	condition:
		( uint16(0)==0x3f3c or uint16(0)==0x253c) and filesize <40 and $x1
}
