rule webshell_phpencode_base64
{
	meta:
		description = "Multiple base64 encoded php code"
		author = "JPCERT/CC Incident Response Group"
		hash = "b0fb71780645bacb0f9cae41310a43ef4fa3548961ca4b2adb23464ad9ec2f10"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str1 = "KSkpKSkpKSkpKSkpOw=='));"
		$str2 = "eval(base64_decode('ZnVuY3Rpb24gX"

	condition:
		uint32(0)==0x68703F3C and all of them
}
