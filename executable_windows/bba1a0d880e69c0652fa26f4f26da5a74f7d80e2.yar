rule cred_ie7
{
	meta:
		author = "x0r"
		description = "Steal IE 7 credential"
		version = "0.1"
		os = "windows"
		filetype = "executable"

	strings:
		$f1 = "Crypt32.dll" nocase
		$c1 = "CryptUnprotectData"
		$s1 = "abe2869f-9b47-4cd9-a358-c22904dba7f7" nocase

	condition:
		all of them
}
