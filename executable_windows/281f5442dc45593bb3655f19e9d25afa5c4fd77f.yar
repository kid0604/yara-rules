rule APT_Loader_Raw32_REDFLARE_1
{
	meta:
		date_created = "2020-11-27"
		date_modified = "2020-11-27"
		md5 = "4022baddfda3858a57c9cbb0d49f6f86"
		rev = 1
		author = "FireEye"
		description = "Detects APT Loader Raw32 REDFLARE variant 1"
		os = "windows"
		filetype = "executable"

	strings:
		$load = { EB ?? 58 [0-4] 8B 10 8B 48 [1-3] 8B C8 83 C1 ?? 03 D1 83 E9 [1-3] 83 C1 [1-4] FF D? }

	condition:
		( uint16(0)!=0x5A4D) and all of them
}
