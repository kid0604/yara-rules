rule WebShell_lamashell
{
	meta:
		description = "PHP Webshells Github Archive - file lamashell.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "b71181e0d899b2b07bc55aebb27da6706ea1b560"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "if(($_POST['exe']) == \"Execute\") {" fullword
		$s8 = "$curcmd = $_POST['king'];" fullword
		$s16 = "\"http://www.w3.org/TR/html4/loose.dtd\">" fullword
		$s18 = "<title>lama's'hell v. 3.0</title>" fullword
		$s19 = "_|_  O    _    O  _|_"
		$s20 = "$curcmd = \"ls -lah\";" fullword

	condition:
		2 of them
}
