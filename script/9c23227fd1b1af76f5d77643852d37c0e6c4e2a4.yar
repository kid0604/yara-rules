rule WebShell_Generic_PHP_1
{
	meta:
		description = "PHP Webshells Github Archive - from files Dive Shell 1.0"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		score = 70
		date = "2014/04/06"
		modified = "2022-12-06"
		hash0 = "3b086b9b53cf9d25ff0d30b1d41bb2f45c7cda2b"
		hash1 = "2558e728184b8efcdb57cfab918d95b06d45de04"
		hash2 = "203a8021192531d454efbc98a3bbb8cabe09c85c"
		hash3 = "b79709eb7801a28d02919c41cc75ac695884db27"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = { 76 61 72 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 20 3d 20 6e 65 77 20 41 72 72 61 79 28 3c 3f 70 68 70 20 65 63 68 6f 20 24 6a 73 5f 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 20 3f 3e 29 3b }
		$ = { 69 66 20 28 65 6d 70 74 79 28 24 5f 53 45 53 53 49 4f 4e 5b 27 63 77 64 27 5d 29 20 7c 7c 20 21 65 6d 70 74 79 28 24 5f 52 45 51 55 45 53 54 5b 27 72 65 73 65 74 27 5d 29 29 20 7b }
		$ = { 69 66 20 28 65 2e 6b 65 79 43 6f 64 65 20 3d 3d 20 33 38 20 26 26 20 63 75 72 72 65 6e 74 5f 6c 69 6e 65 20 3c 20 63 6f 6d 6d 61 6e 64 5f 68 69 73 74 2e 6c 65 6e 67 74 68 2d 31 29 20 7b }

	condition:
		1 of them
}
