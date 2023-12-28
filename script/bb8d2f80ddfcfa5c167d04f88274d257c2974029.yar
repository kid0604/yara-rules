rule CryptHunter_pythonDownloader
{
	meta:
		description = "1st stage python downloader in Dangerouspassword"
		author = "JPCERT/CC Incident Response Group"
		hash1 = "e0891a1bfa5980171599dc5fe31d15be0a6c79cc08ab8dc9f09ceec7a029cbdf"
		os = "windows,linux,macos,ios,android"
		filetype = "script"

	strings:
		$str01 = "auto_interrupt_handle" ascii wide fullword
		$str02 = "aW1wb3J0IHN0cmluZw0KaW1wb3J0IHJhbmRvbQ0" ascii wide fullword
		$rot13_01 = "clguba" ascii wide fullword
		$rot13_02 = "log_handle_method" ascii wide fullword
		$rot13_03 = "rot13" ascii wide fullword
		$rot13_04 = "zfvrkrp" ascii wide fullword
		$rot13_05 = "Jvaqbjf" ascii wide fullword
		$rot13_06 = ".zfv" ascii wide fullword
		$rot13_07 = "qrirybcpber" ascii wide fullword
		$rot13_08 = "uggc://ncc." ascii wide fullword
		$rot13_09 = "cat_file_header_ops" ascii wide fullword

	condition:
		( filesize >10KB) and ( filesize <5MB) and (1 of ($str*) or (3 of ($rot13*)))
}
