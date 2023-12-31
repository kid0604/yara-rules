rule WEBSHELL_ASPX_SimpleSeeSharp : Webshell Unclassified
{
	meta:
		author = "threatintel@volexity.com"
		date = "2021-03-01"
		description = "A simple ASPX Webshell that allows an attacker to write further files to disk."
		hash = "893cd3583b49cb706b3e55ecb2ed0757b977a21f5c72e041392d1256f31166e2"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		os = "windows"
		filetype = "script"

	strings:
		$header = "<%@ Page Language=\"C#\" %>"
		$body = "<% HttpPostedFile thisFile = Request.Files[0];thisFile.SaveAs(Path.Combine"

	condition:
		$header at 0 and $body and filesize <1KB
}
