import "pe"

rule HKTL_NET_GUID_Sharp_Suite_alt_1
{
	meta:
		description = "Detects c# red/black-team tools via typelibguid"
		reference = "https://github.com/FuzzySecurity/Sharp-Suite"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Arnim Rupp (https://github.com/ruppde)"
		date = "2020-12-13"
		modified = "2023-04-06"
		modified = "2023-04-06"
		os = "windows"
		filetype = "executable"

	strings:
		$typelibguid0lo = "19657be4-51ca-4a85-8ab1-f6666008b1f3" ascii wide
		$typelibguid0up = "19657BE4-51CA-4A85-8AB1-F6666008B1F3" ascii wide
		$typelibguid1lo = "0a382d9a-897f-431a-81c2-a4e08392c587" ascii wide
		$typelibguid1up = "0A382D9A-897F-431A-81C2-A4E08392C587" ascii wide
		$typelibguid2lo = "467ee2a9-2f01-4a71-9647-2a2d9c31e608" ascii wide
		$typelibguid2up = "467EE2A9-2F01-4A71-9647-2A2D9C31E608" ascii wide
		$typelibguid3lo = "eacaa2b8-43e5-4888-826d-2f6902e16546" ascii wide
		$typelibguid3up = "EACAA2B8-43E5-4888-826D-2F6902E16546" ascii wide
		$typelibguid4lo = "629f86e6-44fe-4c9c-b043-1c9b64be6d5a" ascii wide
		$typelibguid4up = "629F86E6-44FE-4C9C-B043-1C9B64BE6D5A" ascii wide
		$typelibguid5lo = "ecf2ffe4-1744-4745-8693-5790d66bb1b8" ascii wide
		$typelibguid5up = "ECF2FFE4-1744-4745-8693-5790D66BB1B8" ascii wide
		$typelibguid6lo = "0a621f4c-8082-4c30-b131-ba2c98db0533" ascii wide
		$typelibguid6up = "0A621F4C-8082-4C30-B131-BA2C98DB0533" ascii wide
		$typelibguid7lo = "72019dfe-608e-4ab2-a8f1-66c95c425620" ascii wide
		$typelibguid7up = "72019DFE-608E-4AB2-A8F1-66C95C425620" ascii wide
		$typelibguid8lo = "f0d28809-b712-4380-9a59-407b7b2badd5" ascii wide
		$typelibguid8up = "F0D28809-B712-4380-9A59-407B7B2BADD5" ascii wide
		$typelibguid9lo = "956a5a4d-2007-4857-9259-51cd0fb5312a" ascii wide
		$typelibguid9up = "956A5A4D-2007-4857-9259-51CD0FB5312A" ascii wide
		$typelibguid10lo = "a3b7c697-4bb6-455d-9fda-4ab54ae4c8d2" ascii wide
		$typelibguid10up = "A3B7C697-4BB6-455D-9FDA-4AB54AE4C8D2" ascii wide
		$typelibguid11lo = "a5f883ce-1f96-4456-bb35-40229191420c" ascii wide
		$typelibguid11up = "A5F883CE-1F96-4456-BB35-40229191420C" ascii wide
		$typelibguid12lo = "28978103-d90d-4618-b22e-222727f40313" ascii wide
		$typelibguid12up = "28978103-D90D-4618-B22E-222727F40313" ascii wide
		$typelibguid13lo = "0c70c839-9565-4881-8ea1-408c1ebe38ce" ascii wide
		$typelibguid13up = "0C70C839-9565-4881-8EA1-408C1EBE38CE" ascii wide
		$typelibguid14lo = "fa1d9a36-415a-4855-8c01-54b6e9fc6965" ascii wide
		$typelibguid14up = "FA1D9A36-415A-4855-8C01-54B6E9FC6965" ascii wide
		$typelibguid15lo = "252676f8-8a19-4664-bfb8-5a947e48c32a" ascii wide
		$typelibguid15up = "252676F8-8A19-4664-BFB8-5A947E48C32A" ascii wide
		$typelibguid16lo = "447edefc-b429-42bc-b3bc-63a9af19dbd6" ascii wide
		$typelibguid16up = "447EDEFC-B429-42BC-B3BC-63A9AF19DBD6" ascii wide
		$typelibguid17lo = "04d0b3a6-eaab-413d-b9e2-512fa8ebd02f" ascii wide
		$typelibguid17up = "04D0B3A6-EAAB-413D-B9E2-512FA8EBD02F" ascii wide
		$typelibguid18lo = "5611236e-2557-45b8-be29-5d1f074d199e" ascii wide
		$typelibguid18up = "5611236E-2557-45B8-BE29-5D1F074D199E" ascii wide
		$typelibguid19lo = "53f622eb-0ca3-4e9b-9dc8-30c832df1c7b" ascii wide
		$typelibguid19up = "53F622EB-0CA3-4E9B-9DC8-30C832DF1C7B" ascii wide
		$typelibguid20lo = "414187db-5feb-43e5-a383-caa48b5395f1" ascii wide
		$typelibguid20up = "414187DB-5FEB-43E5-A383-CAA48B5395F1" ascii wide

	condition:
		( uint16(0)==0x5A4D and uint32( uint32(0x3C))==0x00004550) and any of them
}
