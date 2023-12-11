rule php_file : webshell
{
	meta:
		description = "Laudanum Injector Tools - file file.php"
		author = "Florian Roth"
		reference = "http://laudanum.inguardians.com/"
		date = "2015-06-22"
		hash = "7421d33e8007c92c8642a36cba7351c7f95a4335"
		os = "windows,linux,macos"
		filetype = "script"

	strings:
		$s1 = "$allowedIPs =" fullword ascii
		$s2 = "<a href=\"<?php echo $_SERVER['PHP_SELF']  ?>\">Home</a><br/>" fullword ascii
		$s3 = "$dir  = isset($_GET[\"dir\"])  ? $_GET[\"dir\"]  : \".\";" fullword ascii
		$s4 = "$curdir .= substr($curdir, -1) != \"/\" ? \"/\" : \"\";" fullword ascii

	condition:
		filesize <10KB and all of them
}
