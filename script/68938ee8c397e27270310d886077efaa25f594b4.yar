rule webshell_jsp_list_alt_1
{
	meta:
		description = "Web Shell - file list.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "1ea290ff4259dcaeb680cec992738eda"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<FORM METHOD=\"POST\" NAME=\"myform\" ACTION=\"\">" fullword
		$s2 = "out.print(\") <A Style='Color: \" + fcolor.toString() + \";' HRef='?file=\" + fn"
		$s7 = "if(flist[i].canRead() == true) out.print(\"r\" ); else out.print(\"-\");" fullword

	condition:
		all of them
}
