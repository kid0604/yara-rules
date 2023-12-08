rule WebShell_qsd_php_backdoor
{
	meta:
		description = "PHP Webshells Github Archive - file qsd-php-backdoor.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "4856bce45fc5b3f938d8125f7cdd35a8bbae380f"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "// A robust backdoor script made by Daniel Berliner - http://www.qsdconsulting.c"
		$s2 = "if(isset($_POST[\"newcontent\"]))" fullword
		$s3 = "foreach($parts as $val)//Assemble the path back together" fullword
		$s7 = "$_POST[\"newcontent\"]=urldecode(base64_decode($_POST[\"newcontent\"]));" fullword

	condition:
		2 of them
}
