import "pe"

rule docs_invoice_173
{
	meta:
		description = "IcedID - file docs_invoice_173.iso"
		author = "The DFIR Report"
		reference = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
		date = "2022-04-24"
		hash1 = "5bc00ad792d4ddac7d8568f98a717caff9d5ef389ed355a15b892cc10ab2887b"
		os = "windows"
		filetype = "executable"

	strings:
		$x1 = "dar.dll,DllRegisterServer!%SystemRoot%\\System32\\SHELL32.dll" fullword wide
		$x2 = "C:\\Windows\\System32\\rundll32.exe" fullword ascii
		$s3 = "C:\\Users\\admin\\Desktop\\data" fullword wide
		$s4 = "Desktop (C:\\Users\\admin)" fullword wide
		$s5 = "AppPolicyGetProcessTerminationMethod" fullword ascii
		$s6 = "1t3Eo8.dll" fullword ascii
		$s7 = ")..\\..\\..\\..\\Windows\\System32\\rundll32.exe" fullword wide
		$s8 = "DAR.DLL." fullword ascii
		$s9 = "dar.dll:h" fullword wide
		$s10 = "document.lnk" fullword wide
		$s11 = "DOCUMENT.LNK" fullword ascii
		$s12 = "6c484a379420bc181ea93528217b7ebf50eae9cb4fc33fb672f26ffc4ab464e29ba2c0acf9e19728e70ef2833eb4d4ab55aafe3f4667e79c188aa8ab75702520" ascii
		$s13 = "03b9db8f12f0242472abae714fbef30d7278c4917617dc43b61a81951998d867efd5b8a2ee9ff53ea7fa4110c9198a355a5d7f3641b45f3f8bb317aac02aa1fb" ascii
		$s14 = "d1e5711e46fcb02d7cc6aa2453cfcb8540315a74f93c71e27fa0cf3853d58b979d7bb7c720c02ed384dea172a36916f1bb8b82ffd924b720f62d665558ad1d8c" ascii
		$s15 = "7d0bfdbaac91129f5d74f7e71c1c5524690343b821a541e8ba8c6ab5367aa3eb82b8dd0faee7bf6d15b972a8ae4b320b9369de3eb309c722db92d9f53b6ace68" ascii
		$s16 = "89dd0596b7c7b151bf10a1794e8f4a84401269ad5cc4af9af74df8b7199fc762581b431d65a76ecbff01e3cec318b463bce59f421b536db53fa1d21942d48d93" ascii
		$s17 = "8021dc54625a80e14f829953cc9c4310b6242e49d0ba72eedc0c04383ac5a67c0c4729175e0e662c9e78cede5882532de56a5625c1761aa6fd46b4aefe98453a" ascii
		$s18 = "24ed05de22fc8d3f76c977faf1def1d729c6b24abe3e89b0254b5b913395ee3487879287388e5ceac4b46182c2072ad1aa4f415ed6ebe515d57f4284ae068851" ascii
		$s19 = "827da8b743ba46e966706e7f5e6540c00cb1205811383a2814e1d611decfc286b1927d20391b22a0a31935a9ab93d7f25e6331a81d13db6d10c7a771e82dfd8b" ascii
		$s20 = "7c33d9ad6872281a5d7bf5984f537f09544fdee50645e9846642206ea4a81f70b27439e6dcbe6fdc1331c59bf3e2e847b6195e8ed2a51adaf91b5e615cece1d3" ascii

	condition:
		uint16(0)==0x0000 and filesize <600KB and 1 of ($x*) and 4 of them
}
