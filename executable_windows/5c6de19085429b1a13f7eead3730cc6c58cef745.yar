rule Windows_VulnDriver_GlckIo_68d5afbb
{
	meta:
		author = "Elastic Security"
		id = "68d5afbb-a90e-404a-8e77-4b0f9d72934c"
		fingerprint = "98b25bf15be40dcd9cedbce6d50551faa968ac0e8259c1df0181ecb36afc69dd"
		creation_date = "2022-04-04"
		last_modified = "2022-04-04"
		threat_name = "Windows.VulnDriver.GlckIo"
		reference_sample = "5ae23f1fcf3fb735fcf1fa27f27e610d9945d668a149c7b7b0c84ffd6409d99a"
		severity = 50
		arch_context = "x86"
		scan_context = "file"
		license = "Elastic License v2"
		os = "windows"
		description = "Detects Windows vulnerability in GlckIo driver"
		filetype = "executable"

	strings:
		$str1 = "[GLKIO2] Cannot resolve ZwQueryInformationProcess"

	condition:
		int16 ( uint32(0x3C)+0x5c)==0x0001 and int16 ( uint32(0x3C)+0x18)==0x020b and $str1
}
