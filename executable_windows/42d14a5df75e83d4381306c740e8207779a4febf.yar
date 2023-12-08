rule Windows_VulnDriver_WinIo_b0f21a70
{
	meta:
		author = "Elastic Security"
		id = "b0f21a70-b563-4b18-8ef9-73885125e88b"
		fingerprint = "00d8142a30e9815f8e4c53443221fc1c3882c8b6f68e77a8ed7ffe4fc8852488"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.WinIo"
		reference_sample = "9fc29480407e5179aa8ea41682409b4ea33f1a42026277613d6484e5419de374"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in WinIo driver"
		filetype = "executable"

	strings:
		$str1 = "IOCTL_WINIO_WRITEMSR"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and $str1
}
