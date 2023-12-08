rule CN_Honker_Webshell_ASPX_shell_shell
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file shell.aspx"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "1816006827d16ed73cefdd2f11bd4c47c8af43e4"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = "<%try{ System.Reflection.Assembly.Load(Request.BinaryRead(int.Parse(Request.Cook" ascii
		$s1 = "<%@ Page Language=\"C#\" ValidateRequest=\"false\" %>" fullword ascii

	condition:
		filesize <1KB and all of them
}
