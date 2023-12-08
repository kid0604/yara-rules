rule thelast_orice2
{
	meta:
		description = "Webshells Auto-generated - file orice2.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "aa63ffb27bde8d03d00dda04421237ae"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = " $aa = $_GET['aa'];"
		$s1 = "echo $aa;"

	condition:
		all of them
}
