rule webshell_jsp_asd
{
	meta:
		description = "Web Shell - file asd.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "a042c2ca64176410236fcc97484ec599"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s3 = "<%@ page language=\"java\" pageEncoding=\"gbk\"%>" fullword
		$s6 = "<input size=\"100\" value=\"<%=application.getRealPath(\"/\") %>\" name=\"url"

	condition:
		all of them
}
