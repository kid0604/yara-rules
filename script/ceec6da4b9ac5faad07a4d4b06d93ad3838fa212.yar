rule CN_Honker_Webshell_JSP_jsp
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file jsp.html"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c58fed3d3d1e82e5591509b04ed09cb3675dc33a"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "<input name=f size=30 value=shell.jsp>" fullword ascii
		$s2 = "<font color=red>www.i0day.com  By:" fullword ascii

	condition:
		filesize <3KB and all of them
}
