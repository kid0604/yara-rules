rule WEBSHELL_JSP_Nov21_1
{
	meta:
		description = "Detects JSP webshells"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://www.ic3.gov/Media/News/2021/211117-2.pdf"
		date = "2021-11-23"
		score = 70
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$x1 = "request.getParameter(\"pwd\")" ascii
		$x2 = "excuteCmd(request.getParameter(" ascii
		$x3 = "getRuntime().exec (request.getParameter(" ascii
		$x4 = "private static final String PW = \"whoami\"" ascii

	condition:
		filesize <400KB and 1 of them
}
