import "pe"

rule INDICATOR_PY_Packed_PyMinifier
{
	meta:
		author = "ditekSHen"
		description = "Detects python code potentially obfuscated using PyMinifier"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$s1 = "exec(lzma.decompress(base64.b64decode("

	condition:
		( uint32(0)==0x6f706d69 or uint16(0)==0x2123 or uint16(0)==0x0a0d or uint16(0)==0x5a4d) and all of them
}
