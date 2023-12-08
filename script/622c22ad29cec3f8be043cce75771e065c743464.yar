rule CN_Honker_Webshell_ASP_asp404
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file asp404.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "bed51971288aeabba6dabbfb80d2843ec0c4ebf6"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "temp1 = Len(folderspec) - Len(server.MapPath(\"./\")) -1" fullword ascii
		$s1 = "<form name=\"form1\" method=\"post\" action=\"<%= url%>?action=chklogin\">" fullword ascii
		$s2 = "<td>&nbsp;<a href=\"<%=tempurl+f1.name%>\" target=\"_blank\"><%=f1.name%></a></t" ascii

	condition:
		filesize <113KB and all of them
}
