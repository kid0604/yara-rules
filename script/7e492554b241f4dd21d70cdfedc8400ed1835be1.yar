rule cve202120837_webshell_fox
{
	meta:
		description = "CVE-2021-20837 PHP webshell (fox)"
		author = "JPCERT/CC Incident Response Group"
		hash = "654c4a51f8caa0535b04c692114f2f096a4b6b87bd6f9e1bcce216a2158b518d"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$encode1 = "eval(str_rot13(gzinflate(str_rot13(base64_decode("
		$encode2 = "6576616C28677A756E636F6D7072657373286261736536345F6465636F64652827"
		$str1 = "deleteDir("
		$str2 = "http_get_contents1("
		$str3 = "http_get_contents2("
		$str4 = "httpsCurl("

	condition:
		uint32(0)==0x68703F3C and (1 of ($encode*) or all of ($str*))
}
