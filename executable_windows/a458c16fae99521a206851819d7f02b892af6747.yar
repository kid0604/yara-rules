rule Windows_VulnDriver_DirectIo_abe8bfa6
{
	meta:
		author = "Elastic Security"
		id = "abe8bfa6-0b51-4224-a7fc-4249e34ac0a2"
		fingerprint = "f572092a61c4b7f107c397deb6eb9e04d56a0c74ba0a17cc218e33d17e909f18"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.DirectIo"
		reference_sample = "d84e3e250a86227c64a96f6d5ac2b447674ba93d399160850acb2339da43eae5"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in DirectIo driver"
		filetype = "executable"

	strings:
		$str1 = "\\DirectIo64.pdb"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
