rule Windows_Ransomware_Hive_55619cd0
{
	meta:
		author = "Elastic Security"
		id = "55619cd0-6013-45e2-b15e-0dceff9571ab"
		fingerprint = "04df3169c50fbab4e2b495de5500c62ddf5e76aa8b4a7fc8435f39526f69c52b"
		creation_date = "2021-08-26"
		last_modified = "2022-01-13"
		threat_name = "Windows.Ransomware.Hive"
		reference_sample = "50ad0e6e9dc72d10579c20bb436f09eeaa7bfdbcb5747a2590af667823e85609"
		severity = 100
		arch_context = "x86"
		scan_context = "file, memory"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows Ransomware Hive"
		filetype = "executable"

	strings:
		$a1 = "google.com/encryptor.(*App).KillProcesses" ascii fullword
		$a2 = "- Do not shutdown or reboot your computers, unmount external storages." ascii fullword
		$a3 = "hive"

	condition:
		all of them
}
