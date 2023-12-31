rule malware_windows_apt_whitebear_binary_loader_2
{
	meta:
		description = "The WhiteBear loader contains a set of messaging and injection components that support continued presence on victim hosts"
		reference = "https://securelist.com/introducing-whitebear/81638/"
		author = "@fusionrace"
		md5 = "06bd89448a10aa5c2f4ca46b4709a879"
		os = "windows"
		filetype = "executable"

	strings:
		$b1 = "i cunt waiting anymore #%d" wide ascii
		$b2 = "lights aint turnt off with #%d" wide ascii
		$b3 = "Not find process" wide ascii
		$b4 = "CMessageProcessingSystem::Receive_TAKE_NOP" wide ascii
		$b5 = "CMessageProcessingSystem::Receive_TAKE_CAN_NOT_WORK" wide ascii

	condition:
		3 of ($b*)
}
