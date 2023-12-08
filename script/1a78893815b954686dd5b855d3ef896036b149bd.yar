rule webshell_jsp_jshell
{
	meta:
		description = "Web Shell - file jshell.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "124b22f38aaaf064cef14711b2602c06"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "kXpeW[\"" fullword
		$s4 = "[7b:g0W@W<" fullword
		$s5 = "b:gHr,g<" fullword
		$s8 = "RhV0W@W<" fullword
		$s9 = "S_MR(u7b" fullword

	condition:
		all of them
}
