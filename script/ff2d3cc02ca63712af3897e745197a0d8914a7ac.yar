rule md5_b579bff90970ec58862ea8c26014d643
{
	meta:
		description = "Detects files with specific extension and ForceType application/x-httpd-php"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = /<Files [^>]+.(jpg|png|gif)>\s*ForceType application\/x-httpd-php/

	condition:
		any of them
}
