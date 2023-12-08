import "math"

rule WEBSHELL_Mixed_OBFUSC
{
	meta:
		description = "Detects webshell with mixed obfuscation commands"
		author = "Arnim Rupp (https://github.com/ruppde)"
		reference = "Internal Research"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		date = "2023-01-28"
		modified = "2023-04-05"
		hash1 = "8c4e5c6bdfcc86fa27bdfb075a7c9a769423ec6d53b73c80cbc71a6f8dd5aace"
		hash2 = "78f2086b6308315f5f0795aeaa75544128f14889a794205f5fc97d7ca639335b"
		hash3 = "3bca764d44074820618e1c831449168f220121698a7c82e9909f8eab2e297cbd"
		hash4 = "b26b5e5cba45482f486ff7c75b54c90b7d1957fd8e272ddb4b2488ec65a2936e"
		hash5 = "e217be2c533bfddbbdb6dc6a628e0d8756a217c3ddc083894e07fd3a7408756c"
		score = 50
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "rawurldecode/*" ascii
		$s2 = "preg_replace/*" ascii
		$s3 = " __FILE__/*" ascii
		$s4 = "strlen/*" ascii
		$s5 = "str_repeat/*" ascii
		$s6 = "basename/*" ascii

	condition:
		( uint16(0)==0x3f3c and filesize <200KB and (4 of them ))
}
