rule malware_windows_apt_whitebear_binary_loader_3
{
	meta:
		description = "The WhiteBear loader contains a set of messaging and injection components that support continued presence on victim hosts"
		reference = "https://securelist.com/introducing-whitebear/81638/"
		author = "@fusionrace"
		md5 = "b099b82acb860d9a9a571515024b35f0"
		os = "windows"
		filetype = "executable"

	strings:
		$c1 = "{531511FA-190D-5D85-8A4A-279F2F592CC7}" wide ascii
		$c2 = "IsLoaderAlreadyWork" wide ascii
		$c3 = "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-%03x%01x-%01x" wide ascii
		$c4 = "\\\\.\\pipe\\Winsock2\\CatalogChangeListener-%02x%02x-%01x" wide ascii

	condition:
		all of ($c*)
}
