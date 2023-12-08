import "pe"

rule emotet_packer
{
	meta:
		description = "recent Emotet packer pdb string"
		author = "Marc Salinas (@Bondey_m)"
		reference = "330fb2954c1457149988cda98ca8401fbc076802ff44bb30894494b1c5531119"
		reference = "d08a4dc159b17bde8887fa548b7d265108f5f117532d221adf7591fbad29b457"
		reference = "7b5b8aaef86b1a7a8e7f28f0bda0bb7742a8523603452cf38170e5253f7a5c82"
		reference = "e6abb24c70a205ab471028aee22c1f32690c02993b77ee0e77504eb360860776"
		reference = "5684850a7849ab475227da91ada8ac5741e36f98780d9e3b01ae3085a8ef02fc"
		reference = "acefdb67d5c0876412e4d079b38da1a5e67a7fcd936576c99cc712391d3a5ff5"
		reference = "14230ba12360a172f9f242ac98121ca76e7c4450bfcb499c2af89aa3a1ef7440"
		reference = "4fe9b38d2c32d0ee19d7be3c1a931b9448904aa72e888f40f43196e0b2207039"
		reference = "e31028282c38cb13dd4ede7e9c8aa62d45ddae5ebaa0fe3afb3256601dbf5de7"
		date = "2017-12-12"
		os = "windows"
		filetype = "executable"

	strings:
		$pdb1 = "123EErrrtools.pdb"
		$pdb2 = "gGEW\\F???/.pdb"

	condition:
		$pdb1 or $pdb2
}
