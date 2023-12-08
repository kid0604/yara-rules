import "pe"

rule turla_png_reg_enum_payload
{
	meta:
		author = "Ben Humphrey"
		description = "Payload that has most recently been dropped by the Turla PNG Dropper"
		reference = "https://www.nccgroup.trust/uk/about-us/newsroom-and-events/blogs/2018/november/turla-png-dropper-is-back/"
		date = "2018/11/23"
		hash1 = "fea27eb2e939e930c8617dcf64366d1649988f30555f6ee9cd09fe54e4bc22b3"
		os = "windows"
		filetype = "executable"

	strings:
		$crypt00 = "Microsoft Software Key Storage Provider" wide
		$crypt01 = "ChainingModeCBC" wide

	condition:
		( uint16(0)==0x5A4D and uint16( uint32(0x3c))==0x4550) and pe.imports("advapi32.dll","StartServiceCtrlDispatcherA") and pe.imports("advapi32.dll","RegEnumValueA") and pe.imports("advapi32.dll","RegEnumKeyExA") and pe.imports("ncrypt.dll","NCryptOpenStorageProvider") and pe.imports("ncrypt.dll","NCryptEnumKeys") and pe.imports("ncrypt.dll","NCryptOpenKey") and pe.imports("ncrypt.dll","NCryptDecrypt") and pe.imports("ncrypt.dll","BCryptGenerateSymmetricKey") and pe.imports("ncrypt.dll","BCryptGetProperty") and pe.imports("ncrypt.dll","BCryptDecrypt") and pe.imports("ncrypt.dll","BCryptEncrypt") and all of them
}
