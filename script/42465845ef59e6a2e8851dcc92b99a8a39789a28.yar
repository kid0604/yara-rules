rule WEBSHELL_ASP_Embedded_Mar21_1
{
	meta:
		description = "Detects ASP webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "Internal Research"
		date = "2021-03-05"
		score = 85
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<script runat=\"server\">" nocase
		$s2 = "new System.IO.StreamWriter(Request.Form["
		$s3 = ".Write(Request.Form["

	condition:
		filesize <100KB and all of them
}
