rule HKTL_NET_GUID_HastySeries
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/obscuritylabs/HastySeries"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "8435531d-675c-4270-85bf-60db7653bcf6" ascii nocase wide
		$typelibguid1 = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii nocase wide
		$typelibguid2 = "300c7489-a05f-4035-8826-261fa449dd96" ascii nocase wide
		$typelibguid3 = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii nocase wide
		$typelibguid4 = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii nocase wide
		$typelibguid5 = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii nocase wide
		$typelibguid6 = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii nocase wide
		$typelibguid7 = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii nocase wide
		$typelibguid8 = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii nocase wide
		$typelibguid9 = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
