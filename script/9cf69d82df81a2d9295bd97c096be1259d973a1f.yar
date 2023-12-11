rule WebShell_php_webshells_spygrup
{
	meta:
		description = "PHP Webshells Github Archive - file spygrup.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "12f9105332f5dc5d6360a26706cd79afa07fe004"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s2 = "kingdefacer@msn.com</FONT></CENTER></B>\");" fullword
		$s6 = "if($_POST['root']) $root = $_POST['root'];" fullword
		$s12 = "\".htmlspecialchars($file).\" Bu Dosya zaten Goruntuleniyor<kingdefacer@msn.com>" fullword
		$s18 = "By KingDefacer From Spygrup.org>" fullword

	condition:
		3 of them
}
