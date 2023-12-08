rule CoinMiner_WannaMine_Opcodes
{
	meta:
		description = "Detect the risk of Wannamine Rule 3"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = {558BEC83EC10A05BE241008B550C8BCA}
		$s2 = {8B45008954243C03D081FAA00500000F}
		$s3 = {558BEC6AFF68786F410064A100000000}

	condition:
		uint16(0)==0x5a4d and all of them
}
