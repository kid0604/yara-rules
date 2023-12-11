rule WebShell_Generic_PHP_9
{
	meta:
		description = "PHP Webshells Github Archive - from files KAdot Universal Shell v0.1.6.php, KAdot_Universal_Shell_v0.1.6.php, KA_uShell 0.1.6.php"
		author = "Florian Roth (Nextron Systems)"
		super_rule = 1
		date = "2014/04/06"
		modified = "2022-12-06"
		score = 70
		reference = "Internal Research"
		hash0 = "89f2a7007a2cd411e0a7abd2ff5218d212b84d18"
		hash1 = "2266178ad4eb72c2386c0a4d536e5d82bb7ed6a2"
		hash2 = "0daed818cac548324ad0c5905476deef9523ad73"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$ = { 3a 3c 62 3e 22 20 2e 62 61 73 65 36 34 5f 64 65 63 6f 64 65 28 24 5f 50 4f 53 54 5b 27 74 6f 74 27 5d 29 2e 20 22 3c 2f 62 3e 22 3b }
		$ = { 69 66 20 28 69 73 73 65 74 28 24 5f 50 4f 53 54 5b 27 77 71 27 5d 29 20 26 26 20 24 5f 50 4f 53 54 5b 27 77 71 27 5d 3c 3e 22 22 29 20 7b }
		$ = { 70 61 73 73 74 68 72 75 28 24 5f 50 4f 53 54 5b 27 63 27 5d 29 3b }
		$ = { 3c 69 6e 70 75 74 20 74 79 70 65 3d 22 72 61 64 69 6f 22 20 6e 61 6d 65 3d 22 74 61 63 22 20 76 61 6c 75 65 3d 22 31 22 3e 42 36 34 20 44 65 63 6f 64 65 3c 62 72 3e }

	condition:
		1 of them
}
