import "math"

rule WEBSHELL_PHP_In_Htaccess
{
	meta:
		description = "Use Apache .htaccess to execute php code inside .htaccess"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		score = 75
		date = "2021/01/07"
		modified = "2023-07-05"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "d79e9b13a32a9e9f3fa36aa1a4baf444bfd2599a"
		hash = "e1d1091fee6026829e037b2c70c228344955c263"
		hash = "c026d4512a32d93899d486c6f11d1e13b058a713"
		hash = "8c9e65cd3ef093cd9c5b418dc5116845aa6602bc92b9b5991b27344d8b3f7ef2"
		os = "linux"
		filetype = "script"

	strings:
		$hta = "AddType application/x-httpd-php .htaccess" wide ascii

	condition:
		filesize <100KB and $hta
}
