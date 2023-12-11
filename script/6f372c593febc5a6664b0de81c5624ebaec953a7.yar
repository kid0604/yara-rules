rule APT_WEBSHELL_Tiny_WebShell : APT Hafnium WebShell
{
	meta:
		description = "Detects WebShell Injection"
		author = "Markus Neis,Swisscom"
		hash = "099c8625c58b315b6c11f5baeb859f4c"
		date = "2021-03-05"
		reference = "https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/"
		os = "windows,linux"
		filetype = "script"

	strings:
		$x1 = "<%@ Page Language=\"Jscript\" Debug=true%>"
		$s1 = "=Request.Form(\""
		$s2 = "eval("

	condition:
		filesize <300 and all of ($s*) and $x1
}
