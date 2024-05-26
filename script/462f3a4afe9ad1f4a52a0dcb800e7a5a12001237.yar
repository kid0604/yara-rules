import "math"

rule WEBSHELL_PHP_Dynamic_alt_2
{
	meta:
		description = "PHP webshell using function name from variable, e.g. $a='ev'.'al'; $a($code)"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		date = "2021/01/13"
		modified = "2023-10-06"
		score = 60
		hash = "65dca1e652d09514e9c9b2e0004629d03ab3c3ef"
		hash = "b8ab38dc75cec26ce3d3a91cb2951d7cdd004838"
		hash = "c4765e81550b476976604d01c20e3dbd415366df"
		hash = "2e11ba2d06ebe0aa818e38e24a8a83eebbaae8877c10b704af01bf2977701e73"
		id = "58ad94bc-93c8-509c-9d3a-c9a26538d60c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$pd_fp1 = "whoops_add_stack_frame" wide ascii
		$pd_fp2 = "new $ec($code, $mode, $options, $userinfo);" wide ascii
		$pd_fp3 = "($i)] = 600;" ascii
		$php_short = "<?" wide ascii
		$no_xml1 = "<?xml version" nocase wide ascii
		$no_xml2 = "<?xml-stylesheet" nocase wide ascii
		$no_asp1 = "<%@LANGUAGE" nocase wide ascii
		$no_asp2 = /<script language="(vb|jscript|c#)/ nocase wide ascii
		$no_pdf = "<?xpacket"
		$php_new1 = /<\?=[^?]/ wide ascii
		$php_new2 = "<?php" nocase wide ascii
		$php_new3 = "<script language=\"php" nocase wide ascii
		$dynamic1 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\$/ wide ascii
		$dynamic2 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\("/ wide ascii
		$dynamic3 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\('/ wide ascii
		$dynamic4 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(str/ wide ascii
		$dynamic5 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(\)/ wide ascii
		$dynamic6 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(@/ wide ascii
		$dynamic7 = /\$[a-zA-Z_\x80-\xff][a-zA-Z0-9_\x80-\xff\[\]'"]{0,20}\s{0,20}\(base64_decode/ wide ascii
		$dynamic8 = /\$\{[^}]{1,20}}(\[[^\]]{1,20}\])?\(\$\{/ wide ascii
		$fp1 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 24 63 29 3B }
		$fp2 = { 3C 3F 70 68 70 0A 0A 24 61 28 24 62 20 3D 20 33 2C 20 2E 2E 2E 20 24 63 29 3B }
		$fp3 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 74 61 74 69 63 3A 3A 24 62 28 29 3B}
		$fp4 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 6E 65 77 20 73 65 6C 66 3A 3A 24 62 28 29 3B }
		$fp5 = { 3C 3F 70 68 70 0A 0A 24 61 20 3D 20 5C 22 7B 24 76 61 72 43 61 6C 6C 61 62 6C 65 28 29 7D 5C 22 3B }
		$fp6 = "// TODO error about missing expression"
		$fp7 = "// This is an invalid location for an attribute, "
		$fp8 = "/* Auto-generated from php/php-langspec tests */"

	condition:
		filesize >20 and filesize <200 and ((($php_short in (0..100) or $php_short in ( filesize -1000.. filesize )) and not any of ($no_*)) or any of ($php_new*)) and ( any of ($dynamic*)) and not any of ($pd_fp*) and not 1 of ($fp*)
}
