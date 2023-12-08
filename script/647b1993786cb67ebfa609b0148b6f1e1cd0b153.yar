rule Unknown_8af033424f9590a15472a23cc3236e68070b952e
{
	meta:
		description = "Detects a web shell"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/bartblaze/PHP-backdoors"
		date = "2016-09-10"
		hash1 = "3382b5eaaa9ad651ab4793e807032650667f9d64356676a16ae3e9b02740ccf3"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "$check = $_SERVER['DOCUMENT_ROOT']" fullword ascii
		$s2 = "$fp=fopen(\"$check\",\"w+\");" fullword ascii
		$s3 = "fwrite($fp,base64_decode('" ascii

	condition:
		( uint16(0)==0x6324 and filesize <6KB and ( all of ($s*))) or ( all of them )
}
