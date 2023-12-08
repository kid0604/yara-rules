rule CN_Honker_Webshell_ASPX_aspx4
{
	meta:
		description = "Webshell from CN Honker Pentest Toolset - file aspx4.txt"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "Disclosed CN Honker Pentest Toolset"
		date = "2015-06-23"
		score = 70
		hash = "200a8f15ffb6e3af31d28c55588003b5025497eb"
		os = "windows"
		filetype = "script"

	strings:
		$s4 = "File.Delete(cdir.FullName + \"\\\\test\");" fullword ascii
		$s5 = "start<asp:TextBox ID=\"Fport_TextBox\" runat=\"server\" Text=\"c:\\\" Width=\"60" ascii
		$s6 = "<div>Code By <a href =\"http://www.hkmjj.com\">Www.hkmjj.Com</a></div>" fullword ascii

	condition:
		filesize <11KB and all of them
}
