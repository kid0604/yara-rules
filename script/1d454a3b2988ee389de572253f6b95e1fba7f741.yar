rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_3
{
	meta:
		description = "Detects HAFNIUM ASPX files dropped on compromised servers"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.microsoft.com/security/blog/2021/03/02/hafnium-targeting-exchange-servers/"
		date = "2021-03-07"
		score = 85
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "runat=\"server\">void Page_Load(object" ascii wide
		$s2 = "Request.Files[0].SaveAs(Server.MapPath(" ascii wide

	condition:
		filesize <50KB and all of them
}
