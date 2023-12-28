rule WaterPamola_cookieswebshell_php
{
	meta:
		description = "Cookies_webshell in Water Pamola"
		author = "JPCERT/CC Incident Response Group"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$func1 = "@$_POST['cookie'];"
		$func2 = "explode(\"|\", $cookie);"
		$func3 = "openssl_pkey_get_public"
		$func4 = "openssl_public_decrypt"
		$func5 = "@create_function"
		$pubkey1 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCPYZ72hGKjj5T+NBa7Y18yuRBC"

	condition:
		uint32(0)==0x68703F3C and (4 of ($func*) or 1 of ($pubkey*))
}
