import "pe"

rule HKTL_NET_GUID_Pen_Test_Tools_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/awillard1/Pen-Test-Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii wide
		$typelibguid0up = "922E7FDC-33BF-48DE-BC26-A81F85462115" ascii wide
		$typelibguid1lo = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii wide
		$typelibguid1up = "AD5205DD-174D-4332-96D9-98B076D6FD82" ascii wide
		$typelibguid2lo = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii wide
		$typelibguid2up = "B67E7550-F00E-48B3-AB9B-4332B1254A86" ascii wide
		$typelibguid3lo = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii wide
		$typelibguid3up = "5E95120E-B002-4495-90A1-CD3AAB2A24DD" ascii wide
		$typelibguid4lo = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii wide
		$typelibguid4up = "295017F2-DC31-4A87-863D-0B9956C2B55A" ascii wide
		$typelibguid5lo = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii wide
		$typelibguid5up = "ABBAA2F7-1452-43A6-B98E-10B2C8C2BA46" ascii wide
		$typelibguid6lo = "a4043d4c-167b-4326-8be4-018089650382" ascii wide
		$typelibguid6up = "A4043D4C-167B-4326-8BE4-018089650382" ascii wide
		$typelibguid7lo = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii wide
		$typelibguid7up = "51ABFD75-B179-496E-86DB-62EE2A8DE90D" ascii wide
		$typelibguid8lo = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii wide
		$typelibguid8up = "A06DA7F8-F87E-4065-81D8-ABC33CB547F8" ascii wide
		$typelibguid9lo = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii wide
		$typelibguid9up = "EE510712-0413-49A1-B08B-1F0B0B33D6EF" ascii wide
		$typelibguid10lo = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii wide
		$typelibguid10up = "9780DA65-7E25-412E-9AA1-F77D828819D6" ascii wide
		$typelibguid11lo = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii wide
		$typelibguid11up = "7913FE95-3AD5-41F5-BF7F-E28F080724FE" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
