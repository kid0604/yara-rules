rule Unknown_0f06c5d1b32f4994c3b3abf8bb76d5468f105167
{
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "6362372850ac7455fa9461ed0483032a1886543f213a431f81a2ac76d383b47e"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$check = $_SERVER['DOCUMENT_ROOT'] . \"/libraries/lola.php\" ;" fullword ascii
		$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
		$s3 = "fwrite($fp,base64_decode('" ascii

	condition:
		( uint16(0)==0x6324 and filesize <2KB and all of them )
}
