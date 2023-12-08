rule Webshell_and_Exploit_CN_APT_HK : Webshell
{
	meta:
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		description = "Webshell and Exploit Code in relation with APT against Honk Kong protesters"
		date = "10.10.2014"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$a0 = "<script language=javascript src=http://java-se.com/o.js</script>" fullword
		$s0 = "<span style=\"font:11px Verdana;\">Password: </span><input name=\"password\" type=\"password\" size=\"20\">"
		$s1 = "<input type=\"hidden\" name=\"doing\" value=\"login\">"

	condition:
		$a0 or ( all of ($s*))
}
