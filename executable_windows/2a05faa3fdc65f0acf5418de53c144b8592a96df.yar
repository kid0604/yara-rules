rule malware_windows_apt_whitebear_binary_loader_1
{
	meta:
		description = "The WhiteBear loader contains a set of messaging and injection components that support continued presence on victim hosts"
		reference = "https://securelist.com/introducing-whitebear/81638/"
		author = "@fusionrace"
		md5 = "b099b82acb860d9a9a571515024b35f0"
		os = "windows"
		filetype = "executable"

	strings:
		$a1 = "### PE STORAGE ###" wide ascii
		$a2 = "### CRYPTO 0 ###" wide ascii
		$a3 = "### EXTERNAL STORAGE ###" wide ascii
		$a4 = "### CRYPTO 1 ###" wide ascii
		$a5 = "### QUEUES ###" wide ascii
		$a6 = "### TRANSPORT ###" wide ascii
		$a7 = "### EXECUTION SUBSYSTEM ###" wide ascii
		$a8 = "### AUTORUN MANAGER ###" wide ascii
		$a9 = "### INJECT MANAGER ###" wide ascii
		$a10 = "### LOCAL TRANSPORT MANAGER ###" wide ascii

	condition:
		6 of ($a*)
}
