rule WEBSHELL_ASPX_Chopper_Like_Mar21_1
{
	meta:
		description = "Detects Chopper like ASPX Webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-03-31"
		score = 85
		hash1 = "ac44513e5ef93d8cbc17219350682c2246af6d5eb85c1b4302141d94c3b06c90"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "http://f/<script language=\"JScript\" runat=\"server\">var _0x" ascii
		$s2 = "));function Page_Load(){var _0x" ascii
		$s3 = ";eval(Request[_0x" ascii
		$s4 = "','orange','unsafe','" ascii

	condition:
		filesize <3KB and 1 of them or 2 of them
}
