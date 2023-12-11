rule UploadShell_98038f1efa4203432349badabad76d44337319a6
{
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "506a6ab6c49e904b4adc1f969c91e4f1a7dde164be549c6440e766de36c93215"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "$lol = file_get_contents(\"../../../../../wp-config.php\");" fullword ascii
		$s6 = "@unlink(\"./export-check-settings.php\");" fullword ascii
		$s7 = "$xos = \"Safe-mode:[Safe-mode:\".$hsafemode.\"] " fullword ascii

	condition:
		( uint16(0)==0x3f3c and filesize <6KB and ( all of ($s*))) or ( all of them )
}
