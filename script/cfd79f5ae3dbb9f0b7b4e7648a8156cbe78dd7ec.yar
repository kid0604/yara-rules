rule webshell_redirect
{
	meta:
		description = "Web Shell - file redirect.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "97da83c6e3efbba98df270cc70beb8f8"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s7 = "var flag = \"?txt=\" + (document.getElementById(\"dl\").checked ? \"2\":\"1\" "

	condition:
		all of them
}
