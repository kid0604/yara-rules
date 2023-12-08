rule webshell_jsp_k81
{
	meta:
		description = "Web Shell - file k81.jsp"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		date = "2014/01/28"
		score = 70
		hash = "41efc5c71b6885add9c1d516371bd6af"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "byte[] binary = BASE64Decoder.class.newInstance().decodeBuffer(cmd);" fullword
		$s9 = "if(cmd.equals(\"Szh0ZWFt\")){out.print(\"[S]\"+dir+\"[E]\");}" fullword

	condition:
		1 of them
}
