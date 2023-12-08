rule php_killnc : webshell
{
	meta:
		description = "Laudanum Injector Tools - file killnc.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "c0dee56ee68719d5ec39e773621ffe40b144fda5"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "if ($_SERVER[\"REMOTE_ADDR\"] == $IP)" fullword ascii
		$s2 = "header(\"HTTP/1.0 404 Not Found\");" fullword ascii
		$s3 = "<?php echo exec('killall nc');?>" fullword ascii
		$s4 = "<title>Laudanum Kill nc</title>" fullword ascii
		$s5 = "foreach ($allowedIPs as $IP) {" fullword ascii

	condition:
		filesize <15KB and 4 of them
}
