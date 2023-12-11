rule webshell_jsp_hsxa
{
	meta:
		description = "Web Shell - file hsxa.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "d0e05f9c9b8e0b3fa11f57d9ab800380"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%><jsp:directive.page import=\"ja"

	condition:
		all of them
}
