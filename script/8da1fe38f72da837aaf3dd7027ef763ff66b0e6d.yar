import "math"

rule WEBSHELL_PHP_Writer
{
	meta:
		description = "PHP webshell which only writes an uploaded file to disk"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/04/17"
		modified = "2023-07-05"
		score = 50
		hash = "ec83d69512aa0cc85584973f5f0850932fb1949fb5fb2b7e6e5bbfb121193637"
		hash = "407c15f94a33232c64ddf45f194917fabcd2e83cf93f38ee82f9720e2635fa64"
		hash = "988b125b6727b94ce9a27ea42edc0ce282c5dfeb"
		hash = "0ce760131787803bbef216d0ee9b5eb062633537"
		hash = "20281d16838f707c86b1ff1428a293ed6aec0e97"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$sus3 = "'upload'" wide ascii
		$sus4 = "\"upload\"" wide ascii
		$sus5 = "\"Upload\"" wide ascii
		$sus6 = "gif89" wide ascii
		$sus16 = "Army" fullword wide ascii
		$sus17 = "error_reporting( 0 )" wide ascii
		$sus18 = "' . '" wide ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$inp1 = "php://input" wide ascii
		$inp2 = /_GET\s?\[/ wide ascii
		$inp3 = /\(\s?\$_GET\s?\)/ wide ascii
		$inp4 = /_POST\s?\[/ wide ascii
		$inp5 = /\(\s?\$_POST\s?\)/ wide ascii
		$inp6 = /_REQUEST\s?\[/ wide ascii
		$inp7 = /\(\s?\$_REQUEST\s?\)/ wide ascii
		$inp15 = "_SERVER['HTTP_" wide ascii
		$inp16 = "_SERVER[\"HTTP_" wide ascii
		$inp17 = /getenv[\t ]{0,20}\([\t ]{0,20}['"]HTTP_/ wide ascii
		$inp18 = "array_values($_SERVER)" wide ascii
		$inp19 = /file_get_contents\("https?:\/\// wide ascii
		$php_multi_write1 = "fopen(" wide ascii
		$php_multi_write2 = "fwrite(" wide ascii
		$php_write1 = "move_uploaded_file" fullword wide ascii
		$php_write2 = "copy" fullword wide ascii

	condition:
		((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and ( any of ($inp*)) and ( any of ($php_write*) or all of ($php_multi_write*)) and ( filesize <400 or ( filesize <4000 and 1 of ($sus*)))
}
