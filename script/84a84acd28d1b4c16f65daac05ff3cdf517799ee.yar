rule md5_3ccdd51fe616c08daafd601589182d38
{
	meta:
		description = "Detects the use of xxtea_decrypt function in scripts"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = "eval(xxtea_decrypt"

	condition:
		any of them
}
