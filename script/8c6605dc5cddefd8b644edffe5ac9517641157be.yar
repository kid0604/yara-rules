rule webshell_ASP_RemExp
{
	meta:
		description = "Web Shell - file RemExp.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "aa1d8491f4e2894dbdb91eec1abc2244"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<td bgcolor=\"<%=BgColor%>\" title=\"<%=SubFolder.Name%>\"> <a href= \"<%=Reques"
		$s1 = "Private Function ConvertBinary(ByVal SourceNumber, ByVal MaxValuePerIndex, ByVal"

	condition:
		all of them
}
