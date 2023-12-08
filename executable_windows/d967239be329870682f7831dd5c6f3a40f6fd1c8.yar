rule HKTL_NET_GUID_Pen_Test_Tools
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/awillard1/Pen-Test-Tools"
		author = "Arnim Rupp"
		date = "2020-12-13"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0 = "922e7fdc-33bf-48de-bc26-a81f85462115" ascii nocase wide
		$typelibguid1 = "ad5205dd-174d-4332-96d9-98b076d6fd82" ascii nocase wide
		$typelibguid2 = "b67e7550-f00e-48b3-ab9b-4332b1254a86" ascii nocase wide
		$typelibguid3 = "5e95120e-b002-4495-90a1-cd3aab2a24dd" ascii nocase wide
		$typelibguid4 = "295017f2-dc31-4a87-863d-0b9956c2b55a" ascii nocase wide
		$typelibguid5 = "abbaa2f7-1452-43a6-b98e-10b2c8c2ba46" ascii nocase wide
		$typelibguid6 = "a4043d4c-167b-4326-8be4-018089650382" ascii nocase wide
		$typelibguid7 = "51abfd75-b179-496e-86db-62ee2a8de90d" ascii nocase wide
		$typelibguid8 = "a06da7f8-f87e-4065-81d8-abc33cb547f8" ascii nocase wide
		$typelibguid9 = "ee510712-0413-49a1-b08b-1f0b0b33d6ef" ascii nocase wide
		$typelibguid10 = "9780da65-7e25-412e-9aa1-f77d828819d6" ascii nocase wide
		$typelibguid11 = "7913fe95-3ad5-41f5-bf7f-e28f080724fe" ascii nocase wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
