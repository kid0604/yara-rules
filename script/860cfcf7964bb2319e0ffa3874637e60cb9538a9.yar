rule webshell_jsp_action
{
	meta:
		description = "Web Shell - file action.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "5a7d931094f5570aaf5b7b3b06c3d8c0"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "String url=\"jdbc:oracle:thin:@localhost:1521:orcl\";" fullword
		$s6 = "<%@ page contentType=\"text/html;charset=gb2312\"%>" fullword

	condition:
		all of them
}
