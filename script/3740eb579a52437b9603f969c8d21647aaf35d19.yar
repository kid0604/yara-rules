rule M_Hunting_CredTheft_WARPWIRE_1
{
	meta:
		author = "Mandiant"
		description = "This rule detects WARPWIRE, a credential stealer written in JavaScript that is embedded into a legitimate Pulse Secure file."
		md5 = "d0c7a334a4d9dcd3c6335ae13bee59ea"
		reference = "https://www.mandiant.com/resources/blog/suspected-apt-targets-ivanti-zero-day"
		date = "2024-01-11"
		score = 75
		os = "windows"
		filetype = "script"

	strings:
		$s1 = {76 61 72 20 77 64 61 74 61 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 4c 6f 67 69 6e 2e 75 73 65 72 6e 61 6d 65 2e 76 61 6c 75 65 3b}
		$s2 = {76 61 72 20 73 64 61 74 61 20 3d 20 64 6f 63 75 6d 65 6e 74 2e 66 72 6d 4c 6f 67 69 6e 2e 70 61 73 73 77 6f 72 64 2e 76 61 6c 75 65 3b}
		$s3 = {2b 77 64 61 74 61 2b 27 26 27 2b 73 64 61 74 61 3b}
		$s4 = {76 61 72 20 78 68 72 20 3d 20 6e 65 77 20 58 4d 4c 48 74 74 70 52 65 71 75 65 73 74}
		$s5 = "Remember the last selected auth realm for 30 days" ascii

	condition:
		filesize <8KB and all of them
}
