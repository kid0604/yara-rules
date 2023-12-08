rule APT_MAL_ASPX_HAFNIUM_Chopper_Mar21_4
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
		$s1 = "<%@Page Language=\"Jscript\"%>" ascii wide nocase
		$s2 = ".FromBase64String(" ascii wide nocase
		$s3 = "eval(System.Text.Encoding." ascii wide nocase

	condition:
		filesize <850 and all of them
}
