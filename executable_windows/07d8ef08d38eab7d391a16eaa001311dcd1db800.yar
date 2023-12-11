import "pe"

rule HKTL_NET_GUID_HastySeries_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/obscuritylabs/HastySeries"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "8435531d-675c-4270-85bf-60db7653bcf6" ascii wide
		$typelibguid0up = "8435531D-675C-4270-85BF-60DB7653BCF6" ascii wide
		$typelibguid1lo = "47db989f-7e33-4e6b-a4a5-c392b429264b" ascii wide
		$typelibguid1up = "47DB989F-7E33-4E6B-A4A5-C392B429264B" ascii wide
		$typelibguid2lo = "300c7489-a05f-4035-8826-261fa449dd96" ascii wide
		$typelibguid2up = "300C7489-A05F-4035-8826-261FA449DD96" ascii wide
		$typelibguid3lo = "41bf8781-ae04-4d80-b38d-707584bf796b" ascii wide
		$typelibguid3up = "41BF8781-AE04-4D80-B38D-707584BF796B" ascii wide
		$typelibguid4lo = "620ed459-18de-4359-bfb0-6d0c4841b6f6" ascii wide
		$typelibguid4up = "620ED459-18DE-4359-BFB0-6D0C4841B6F6" ascii wide
		$typelibguid5lo = "91e7cdfe-0945-45a7-9eaa-0933afe381f2" ascii wide
		$typelibguid5up = "91E7CDFE-0945-45A7-9EAA-0933AFE381F2" ascii wide
		$typelibguid6lo = "c28e121a-60ca-4c21-af4b-93eb237b882f" ascii wide
		$typelibguid6up = "C28E121A-60CA-4C21-AF4B-93EB237B882F" ascii wide
		$typelibguid7lo = "698fac7a-bff1-4c24-b2c3-173a6aae15bf" ascii wide
		$typelibguid7up = "698FAC7A-BFF1-4C24-B2C3-173A6AAE15BF" ascii wide
		$typelibguid8lo = "63a40d94-5318-42ad-a573-e3a1c1284c57" ascii wide
		$typelibguid8up = "63A40D94-5318-42AD-A573-E3A1C1284C57" ascii wide
		$typelibguid9lo = "56b8311b-04b8-4e57-bb58-d62adc0d2e68" ascii wide
		$typelibguid9up = "56B8311B-04B8-4E57-BB58-D62ADC0D2E68" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
