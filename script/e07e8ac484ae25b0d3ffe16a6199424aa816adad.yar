rule PAS_Webshell_Encoded
{
	meta:
		description = "Detects a PAS webshell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "http://blog.talosintelligence.com/2017/07/the-medoc-connection.html"
		date = "2017-07-11"
		score = 80
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$head1 = "<?php $____=" fullword ascii
		$head2 = "'base'.(32*2).'"
		$enc1 = "isset($_COOKIE['___']" ascii
		$enc2 = "if($___!==NULL){" ascii
		$enc3 = ").substr(md5(strrev($" ascii
		$enc4 = "]))%256);$" ascii
		$enc5 = "]))@setcookie('" ascii
		$enc6 = "]=chr(( ord($_" ascii
		$x1 = { 3D 0A 27 29 29 3B 69 66 28 69 73 73 65 74 28 24 5F 43 4F 4F 4B 49 45 5B 27 }
		$foot1 = "value=\"\"/><input type=\"submit\" value=\"&gt;\"/></form>"
		$foot2 = "();}} @header(\"Status: 404 Not Found\"); ?>"

	condition:
		( uint32(0)==0x68703f3c and filesize <80KB and (3 of them or $head1 at 0 or $head2 in (0..20) or 1 of ($x*))) or $foot1 at ( filesize -52) or $foot2 at ( filesize -44)
}
