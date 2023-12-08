rule Impacket_Tools_Generic_1
{
	meta:
		description = "Compiled Impacket Tools"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://github.com/maaaaz/impacket-examples-windows"
		date = "2017-04-07"
		super_rule = 1
		hash1 = "4f7fad0676d3c3d2d89e8d4e74b6ec40af731b1ddf5499a0b81fc3b1cd797ee3"
		hash2 = "d256d1e05695d62a86d9e76830fcbb856ba7bd578165a561edd43b9f7fdb18a3"
		hash3 = "2d8d500bcb3ffd22ddd8bd68b5b2ce935c958304f03729442a20a28b2c0328c1"
		hash4 = "ab909f8082c2d04f73d8be8f4c2640a5582294306dffdcc85e83a39d20c49ed6"
		hash5 = "e2205539f29972d4e2a83eabf92af18dd406c9be97f70661c336ddf5eb496742"
		hash6 = "27bb10569a872367ba1cfca3cf1c9b428422c82af7ab4c2728f501406461c364"
		hash7 = "dc85a3944fcb8cc0991be100859c4e1bf84062f7428c4dc27c71e08d88383c98"
		hash8 = "0f7f0d8afb230c31fe6cf349c4012b430fc3d6722289938f7e33ea15b2996e1b"
		hash9 = "21d85b36197db47b94b0f4995d07b040a0455ebbe6d413bc33d926ee4e0315d9"
		hash10 = "4c2921702d18e0874b57638433474e54719ee6dfa39d323839d216952c5c834a"
		hash11 = "47afa5fd954190df825924c55112e65fd8ed0f7e1d6fd403ede5209623534d7d"
		hash12 = "7d715217e23a471d42d95c624179fe7de085af5670171d212b7b798ed9bf07c2"
		hash13 = "9706eb99e48e445ac4240b5acb2efd49468a800913e70e40b25c2bf80d6be35f"
		hash14 = "d2856e98011541883e5b335cb46b713b1a6b2c414966a9de122ee7fb226aa7f7"
		hash15 = "8ab2b60aadf97e921e3a9df5cf1c135fbc851cb66d09b1043eaaa1dc01b9a699"
		hash16 = "efff15e1815fb3c156678417d6037ddf4b711a3122c9b5bc2ca8dc97165d3769"
		hash17 = "e300339058a885475f5952fb4e9faaa09bb6eac26757443017b281c46b03108b"
		hash18 = "19544863758341fe7276c59d85f4aa17094045621ca9c98f8a9e7307c290bad4"
		hash19 = "2527fff1a3c780f6a757f13a8912278a417aea84295af1abfa4666572bbbf086"
		hash20 = "202a1d149be35d96e491b0b65516f631f3486215f78526160cf262d8ae179094"
		os = "windows"
		filetype = "executable"

	strings:
		$s1 = "bpywintypes27.dll" fullword ascii
		$s2 = "hZFtPC" fullword ascii
		$s3 = "impacket" ascii

	condition:
		( uint16(0)==0x5a4d and filesize <21000KB and all of ($s*)) or ( all of them )
}
