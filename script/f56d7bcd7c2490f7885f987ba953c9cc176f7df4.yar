rule FSO_s_RemExp
{
	meta:
		description = "Webshells Auto-generated - file RemExp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b69670ecdbb40012c73686cd22696eeb"
		os = "windows,linux"
		filetype = "script"

	strings:
		$s1 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Request.Ser"
		$s5 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=File.Name%>\"> <a href= \"showcode.asp?f=<%=F"
		$s6 = "<td bgcolor=\"<%=BgColor%>\" align=\"right\"><%=Attributes(SubFolder.Attributes)%></"

	condition:
		all of them
}
