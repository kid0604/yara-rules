rule FSO_s_ntdaddy
{
	meta:
		description = "Webshells Auto-generated - file ntdaddy.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "f6262f3ad9f73b8d3e7d9ea5ec07a357"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = "<input type=\"text\" name=\".CMD\" size=\"45\" value=\"<%= szCMD %>\"> <input type=\"s"

	condition:
		all of them
}
