rule Windows_Ransomware_Cuba_95a98e69
{
	meta:
		author = "Elastic Security"
		id = "95a98e69-ce6c-40c6-a05b-2366c663ad6e"
		fingerprint = "05cfd7803692149a55d9ced84828422b66e8b301c8c2aae9ca33c6b68e29bcf8"
		creation_date = "2021-08-04"
		last_modified = "2021-10-04"
		threat_name = "Windows.Ransomware.Cuba"
		reference_sample = "00f18713f860dc8394fb23a1a2b6280d1eb2f20a487c175433a7b495a1ba408d"
		severity = 90
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Cuba"
		filetype = "executable"

	strings:
		$a1 = "We also inform that your databases, ftp server and file server were downloaded by us to our servers." ascii fullword
		$a2 = "Good day. All your files are encrypted. For decryption contact us." ascii fullword
		$a3 = ".cuba" wide fullword

	condition:
		all of them
}
