rule Windows_Hacktool_Mimikatz_b393864f
{
	meta:
		author = "Elastic Security"
		id = "b393864f-a9b0-47e7-aea4-0fc5a4a22a82"
		fingerprint = "bfd497290db97b7578d59e8d43a28ee736a3d7d23072eb67d28ada85cac08bd3"
		creation_date = "2022-04-07"
		last_modified = "2022-04-07"
		description = "Subject: Open Source Developer, Benjamin Delpy"
		threat_name = "Windows.Hacktool.Mimikatz"
		reference_sample = "8206ce9c42582ac980ff5d64f8e3e310bc2baa42d1a206dd831c6ab397fbd8fe"
		severity = 100
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		filetype = "executable"

	strings:
		$subject_name = { 06 03 55 04 03 [2] 4F 70 65 6E 20 53 6F 75 72 63 65 20 44 65 76 65 6C 6F 70 65 72 2C 20 42 65 6E 6A 61 6D 69 6E 20 44 65 6C 70 79 }

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $subject_name
}
