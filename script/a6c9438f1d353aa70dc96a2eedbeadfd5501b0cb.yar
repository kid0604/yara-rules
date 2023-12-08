rule WebShell_Generic_1609_A
{
	meta:
		description = "Auto-generated rule"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		super_rule = 1
		hash1 = "c817a490cfd4d6377c15c9ac9bcfa136f4a45ff5b40c74f15216c030f657d035"
		hash3 = "69b9d55ea2eb4a0d9cfe3b21b0c112c31ea197d1cb00493d1dddc78b90c5745e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "return $qwery45234dws($b);" fullword ascii

	condition:
		( uint16(0)==0x3f3c and 1 of them )
}
