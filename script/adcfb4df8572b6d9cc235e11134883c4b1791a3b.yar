rule webshell_jsp_guige
{
	meta:
		description = "Web Shell - file guige.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "2c9f2dafa06332957127e2c713aacdd2"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "if(damapath!=null &&!damapath.equals(\"\")&&content!=null"

	condition:
		all of them
}
