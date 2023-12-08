rule Ransom_Cerber
{
	meta:
		description = "Detect the risk of Ransomware Cerber Rule 6"
		os = "windows"
		filetype = "executable"

	strings:
		$s0 = {558BEC83EC0C8B45088945FC8B4D0C89}
		$s1 = {8B45AB2603A9D1CBF8490724599ADA8F}

	condition:
		uint16(0)==0x5a4d and all of them
}
