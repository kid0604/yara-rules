rule Windows_Ransomware_Hellokitty_8859e8e8
{
	meta:
		author = "Elastic Security"
		id = "8859e8e8-f94c-4853-b296-1fc801486c57"
		fingerprint = "f9791409d2a058dd68dc09df5e4b597c6c6a1f0da9801d7ab9e678577b621730"
		creation_date = "2021-05-03"
		last_modified = "2021-08-23"
		threat_name = "Windows.Ransomware.Hellokitty"
		reference_sample = "3ae7bedf236d4e53a33f3a3e1e80eae2d93e91b1988da2f7fcb8fde5dcc3a0e9"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Hellokitty"
		filetype = "executable"

	strings:
		$a1 = "HelloKittyMutex" wide fullword
		$a2 = "%s\\read_me_lkd.txt" wide fullword
		$a3 = "Win32_ShadowCopy.ID='%s'" wide fullword
		$a4 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!" wide fullword
		$a5 = "%s/secret/%S" wide fullword
		$a6 = "DECRYPT_NOTE.txt" wide fullword
		$a7 = "Some data has been stored in our servers and ready for publish." wide fullword
		$a9 = "To contact with us you have ONE week from the encryption time, after decryption keys and your personal contact link will be dele" wide
		$a10 = "In case of your disregard, we reserve the right to dispose of the dumped data at our discretion including publishing." wide fullword
		$a11 = "IMPORTANT: Don't modify encrypted files or you can damage them and decryption will be impossible!" wide fullword
		$b1 = "/f /im \"%s\"" wide fullword
		$b2 = "stop \"%s\"" wide fullword
		$b3 = "/f /im %s" wide fullword
		$b4 = "stop %s" wide fullword

	condition:
		(2 of ($a*) and 2 of ($b*)) or (5 of ($a*))
}
