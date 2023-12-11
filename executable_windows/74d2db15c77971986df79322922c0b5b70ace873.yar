rule Ransom_Povlsomware
{
	meta:
		description = "Detect the risk of Ransomware Povlsomware Rule 1"
		os = "windows"
		filetype = "executable"

	strings:
		$Guid = {00002901002466653064356161372D353338662D343266362D396563652D623134313536306637373831}
		$op1 = {0316326505D00?00000228?700000A28?800000AA50?0000020A067B??0000041F5C2E3E067B??0000041F5B2E34067B??0000041F09330E02067B??00000428??0000062D1C067B??0000041F1B331928?900000A20000002005F200000020033071728?A00000A2A027B0?00000403040528??0000062A}
		$s1 = "Decrypting... Please wait" fullword wide
		$s2 = "Please decrypt them!" fullword wide

	condition:
		uint16(0)==0x5a4d and any of them
}
