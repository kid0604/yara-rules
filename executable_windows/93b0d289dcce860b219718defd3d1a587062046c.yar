rule Windows_Ransomware_Hellokitty_4b668121
{
	meta:
		author = "Elastic Security"
		id = "4b668121-cc21-4f0b-b0fc-c2b5b4cb53e8"
		fingerprint = "834316ce0f3225b1654b3c4bccb673c9ad815e422276f61e929d5440ca51a9fa"
		creation_date = "2021-05-03"
		last_modified = "2021-08-23"
		threat_name = "Windows.Ransomware.Hellokitty"
		reference_sample = "9a7daafc56300bd94ceef23eac56a0735b63ec6b9a7a409fb5a9b63efe1aa0b0"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Hellokitty"
		filetype = "executable"

	strings:
		$a1 = "(%d) [%d] %s: STOP DOUBLE PROCESS RUN" ascii fullword
		$a2 = "(%d) [%d] %s: Looking for folder from cmd: %S" ascii fullword
		$a3 = "(%d) [%d] %s: ERROR: Failed to encrypt AES block" ascii fullword
		$a4 = "gHelloKittyMutex" wide fullword
		$a5 = "/C ping 127.0.0.1 & del %s" wide fullword
		$a6 = "Trying to decrypt or modify the files with programs other than our decryptor can lead to permanent loss of data!"
		$a7 = "read_me_lkdtt.txt" wide fullword
		$a8 = "If you want to get it, you must pay us some money and we will help you." wide fullword

	condition:
		5 of them
}
