rule WebShell_Generic_PHP_9_alt_1
{
	meta:
		description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
		author = "Florian Roth"
		super_rule = 1
		hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
		hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
		hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = ":<b>\" .base64_decode($_POST['tot']). \"</b>\";" fullword
		$s6 = "if (isset($_POST['wq']) && $_POST['wq']<>\"\") {" fullword
		$s12 = "if (!empty($_POST['c'])){" fullword
		$s13 = "passthru($_POST['c']);" fullword
		$s16 = "<input type=\"radio\" name=\"tac\" value=\"1\">B64 Decode<br>" fullword
		$s20 = "<input type=\"radio\" name=\"tac\" value=\"3\">md5 Hash" fullword

	condition:
		3 of them
}
