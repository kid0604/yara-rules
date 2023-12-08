rule WebShell_Uploader
{
	meta:
		description = "PHP Webshells Github Archive - file Uploader.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "e216c5863a23fde8a449c31660fd413d77cce0b7"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "move_uploaded_file($userfile, \"entrika.php\"); " fullword

	condition:
		all of them
}
