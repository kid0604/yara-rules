rule CN_Honker_Webshell_JSPMSSQL
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file JSPMSSQL.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "c6b4faecd743d151fe0a4634e37c9a5f6533655f"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "<form action=\"?action=operator&cmd=execute\"" fullword ascii
		$s2 = "String sql = request.getParameter(\"sqlcmd\");" fullword ascii

	condition:
		filesize <35KB and all of them
}
