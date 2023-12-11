rule SUSP_autocad_lsp_malware
{
	meta:
		description = "Recognizes malicious autocad files written in LISP"
		author = "John Lambert @JohnLaTwC"
		date = "2019-02-04"
		reference1 = "http://cadablog.blogspot.com/2012/06/acadmedrea-malware-autocad-based-virus.html"
		hash1 = "1313398e2f39fcf17225c7e915b92bd74292d427163112d70b82f271359b84d5"
		hash2 = "2382e6908e6b44c0676c537cb8caa239c8938cb01e62a45c7247d40ab7dbf0ad"
		hash3 = "23cf3e7f41a755a45e396e5caa3e753e64655b91fe665808f71aa68718670dc8"
		hash4 = "23f018135afc4890e1e09bef9386e45e2236fc43550383b7888cddbdefbcd950"
		hash5 = "4a8da078a02fc49b7f13cd19d10519b1bf31ed0ab04268f018ad4733918e28ff"
		hash6 = "4cca7b530213ef71b2e69a5b11178b61044f93dc60f4e8e568ddb3bb06749ba2"
		hash7 = "5390271899e1ebf884380f5da7d26dff527d13922d3b3f8a3b5ec9152b9dfa40"
		hash8 = "53ef3029f36a3a2b912a722d64eef04f599f6f683c6dcb31a122ab1c98f38700"
		hash9 = "7f7d78931370fa693cbfa50aadecc09b4ab93917dcde3a653bd67fa6dc274cdc"
		hash10 = "8147cc97b6203c7eccfbd10457eb52527f74180ebae79bf3cb9c9edb582e708c"
		hash11 = "8a3113ceb45725539e4ccef5ea1482c29b2bbe0ce7ede72f59f9949a0e04c5cd"
		hash12 = "a0c77993f84ca8fb3096579088326bc907b003327f5885660ea5ba47e2cbc6de"
		hash13 = "a20ac5e0bfa2ee3cb4092907420c23d1f94a1ed1b59cc3d351e5602d7206178c"
		hash14 = "b201969ed7bf782d01011211b48bfccb9dd41a3a5a7456cdff2167f1e4d1b954"
		hash15 = "b2bac49288329a777e7aa7001e9383eec75719c08f2aa8c278b44fabeb74844f"
		hash16 = "b772dce92319bb48df39db6ab701761bd7645a771fd7f394510d5951695e7e96"
		hash17 = "c116cc4db6f77c580c1c4f8acda537ed04e597739bc83011773dbeb77adf93e3"
		hash18 = "ca1b9026b5d69c0981ca088330180d4865602fc2b514fd838664d3e11eab4468"
		hash19 = "d7a814d677f9f9dd9666dc4f4bb9cca88fa90bdb074e87006e8810eef9a0fb32"
		hash20 = "e4acfb69006b8aecf5801e36e2c69ccfeea2e8cbad4ceda9228d2dae2c8fd023"
		hash21 = "f9d6b894ca907145464058a4e2c78de84bf592609b46f3573bfd9e0029e1c778"
		os = "windows"
		filetype = "script"

	strings:
		$s1 = /\(chr\s+\d+\)\s*\(chr\s+\d+\)\s*\(chr\s+\d+\)\s*\(chr\s+\d+\)/
		$s2 = /vl\-list\-\>string\s+\'\(\d+\s+\d+\s+\d+\s+\d+\s+\d+\s+/
		$m1 = "strcat" nocase fullword
		$m2 = "write-line" nocase fullword
		$m3 = "open" nocase fullword
		$m4 = /acad\w*\.lsp\"/ nocase fullword
		$n1 = "vl-registry-write" nocase fullword
		$n2 = "NOHIDDEN" nocase fullword
		$n3 = "vlax-create-object " nocase fullword

	condition:
		filesize <1MB and uint8(0)==0x28 and (1 of ($s*) or all of ($m*) or all of ($n*))
}
