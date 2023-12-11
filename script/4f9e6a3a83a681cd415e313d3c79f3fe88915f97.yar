rule WebShell_Sincap_1_0
{
	meta:
		description = "PHP Webshells Github Archive - file Sincap 1.0.php"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		hash = "9b72635ff1410fa40c4e15513ae3a496d54f971c"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s4 = "</font></span><a href=\"mailto:shopen@aventgrup.net\">" fullword
		$s5 = "<title>:: AventGrup ::.. - Sincap 1.0 | Session(Oturum) B" fullword
		$s9 = "</span>Avrasya Veri ve NetWork Teknolojileri Geli" fullword
		$s12 = "while (($ekinci=readdir ($sedat))){" fullword
		$s19 = "$deger2= \"$ich[$tampon4]\";" fullword

	condition:
		2 of them
}
