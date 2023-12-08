rule WebShell_Simple_PHP_backdoor_by_DK
{
	meta:
		description = "PHP Webshells Github Archive - file Simple_PHP_backdoor_by_DK.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "03f6215548ed370bec0332199be7c4f68105274e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s0 = "<!-- Simple PHP backdoor by DK (http://michaeldaw.org) -->" fullword
		$s1 = "<!--    http://michaeldaw.org   2006    -->" fullword
		$s2 = "Usage: http://target.com/simple-backdoor.php?cmd=cat+/etc/passwd" fullword
		$s6 = "if(isset($_REQUEST['cmd'])){" fullword
		$s8 = "system($cmd);" fullword

	condition:
		2 of them
}
