import "pe"

rule EquationGroup_EquationDrug_Gen_1
{
	meta:
		description = "EquationGroup Malware"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"
		author = "Florian Roth (Nextron Systems)"
		reference = "https://goo.gl/tcSoiJ"
		date = "2017-01-13"
		super_rule = 1
		hash1 = "694be2698bcc5c7a1cce11f8ef65c1c96a883d14b98148c36b32888fb58b6a7e"
		hash2 = "73d1d55493886639c619e9f5e312daab93e4feeb74f24dbe51593842baac8d15"
		hash3 = "e1c9c9f031d902e69e42f684ae5b35a2513f7d5f8bca83dfbab10e8de6254c78"
		hash4 = "c7bf4c012293e7de56d86f4f5b4eeb6c1c5263568cc4d9863a286a86b5daf194"
		hash5 = "2a1f2034e80421359e3bf65cbd12a55a95bd00f2eb86cf2c2d287711ee1d56ad"
		hash6 = "8f5b97124de9fce16e2cfecb7dd2e171824c9e07546db7b3bee7c5f2c92ceda9"
		hash7 = "dfb38ed2ca3870faf351df1bd447a3dc4470ed568553bf83df07bf07967bf520"
		hash8 = "d92928a867a685274b0a74ec55c0b83690fca989699310179e184e2787d47f48"
		hash9 = "137749c0fbb8c12d1a650f0bfc73be2739ff084165d02e4cb68c6496d828bf1d"
		hash10 = "fe42139748c8e9ba27a812466d9395b3a0818b0cd7b41d6769cb7239e57219fb"
		hash11 = "2b27f2faae9de6330f17f60a1d19f9831336f57fdfef06c3b8876498882624a6"
		hash12 = "cdee0daa816f179e74c90c850abd427fbfe0888dcfbc38bf21173f543cdcdc66"
		hash13 = "31d86f77137f0b3697af03dd28d6552258314cecd3c1d9dc18fcf609eb24229a"
		hash14 = "fda57a2ba99bc610d3ff71b2d0ea2829915eabca168df99709a8fdd24288c5e5"
		hash15 = "1097e1d562341858e241f1f67788534c0e340a2dc2e75237d57e3f473e024464"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "Injection Lib -  GetProcAddress failed on Kernel32.DLL function" fullword wide
		$x2 = "Injection Lib -  JUMPUP failed to open requested process" fullword wide

	condition:
		( uint16(0)==0x5a4d and filesize <300KB and 1 of ($x*)) or ( all of them )
}
